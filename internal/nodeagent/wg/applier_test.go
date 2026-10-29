package wg

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type journal struct{ calls []string }

func (j *journal) add(name string) { j.calls = append(j.calls, name) }

type fakeLink struct {
	links, addrs int
	failLink     bool
	failAddr     bool
	log          *journal
}

func (f *fakeLink) record(name string) {
	if f.log == nil {
		f.log = &journal{}
	}
	f.log.add(name)
}

func (f *fakeLink) EnsureLink(string, int) error {
	f.links++
	f.record("link")
	if f.failLink {
		return errTest
	}
	return nil
}

func (f *fakeLink) EnsureAddress(string, netip.Prefix) error {
	f.addrs++
	f.record("address")
	if f.failAddr {
		return errTest
	}
	return nil
}

type fakeDevice struct {
	state         LiveState
	snapshots     int
	configure     int
	last          wgtypes.Config
	failSnapshot  bool
	failConfigure bool
	log           *journal
	snapshotIface string
}

func (f *fakeDevice) record(name string) {
	if f.log == nil {
		f.log = &journal{}
	}
	f.log.add(name)
}

func (f *fakeDevice) Snapshot(iface string) (LiveState, error) {
	f.snapshots++
	f.snapshotIface = iface
	f.record("snapshot")
	if f.failSnapshot {
		return LiveState{}, errTest
	}
	return f.state, nil
}

func (f *fakeDevice) Configure(_ string, cfg wgtypes.Config) error {
	f.configure++
	f.record("configure")
	f.last = cfg
	if f.failConfigure {
		return errTest
	}
	return nil
}

type testError struct{}

func (testError) Error() string { return "boom" }

var errTest = testError{}

func newKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func peerFrom(key wgtypes.Key, prefix string, keepalive int) TargetPeer {
	return TargetPeer{
		PublicKey:    key.PublicKey().String(),
		AllowedIPs:   []netip.Prefix{netip.MustParsePrefix(prefix)},
		KeepaliveSec: keepalive, State: StateActive,
	}
}

func targetFor(private wgtypes.Key, peers ...TargetPeer) Target {
	return Target{
		PrivateKey: private.String(), ListenPort: 51820, MTU: 1420,
		TunnelAddress: netip.MustParsePrefix("10.99.0.1/24"), Peers: peers,
	}
}

func TestApplyDoesNotTouchUnchangedPeers(t *testing.T) {
	priv := newKey(t)
	peer := newKey(t)
	target := targetFor(priv, peerFrom(peer, "10.99.0.2/32", 25))
	log := &journal{}
	dev := &fakeDevice{log: log, state: LiveState{PublicKey: priv.PublicKey().String(), ListenPort: 51820, Peers: map[string]PeerState{
		peer.PublicKey().String(): {
			PublicKey:    peer.PublicKey().String(),
			AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32")},
			KeepaliveSec: 25,
		},
	}}}
	link := &fakeLink{log: log}
	res, err := (&Applier{Link: link, Device: dev, Iface: "wg0"}).Apply(target)
	if err != nil {
		t.Fatal(err)
	}
	if res.Ops != 0 || dev.configure != 0 {
		t.Fatalf("операций %d, вызовов configure %d; ожидалось 0/0", res.Ops, dev.configure)
	}
	if link.links != 1 || link.addrs != 1 || dev.snapshots != 1 {
		t.Fatalf("интерфейс %d, адрес %d, снимков %d; ожидалось 1/1/1", link.links, link.addrs, dev.snapshots)
	}
	if got := strings.Join(log.calls, ","); got != "link,address,snapshot" {
		t.Fatalf("порядок вызовов %q; ожидался link,address,snapshot", got)
	}
}

func TestApplyRemovesAndAdds(t *testing.T) {
	priv := newKey(t)
	add := newKey(t)
	drop := newKey(t)
	log := &journal{}
	dev := &fakeDevice{log: log, state: LiveState{Peers: map[string]PeerState{
		drop.PublicKey().String(): {
			PublicKey:  drop.PublicKey().String(),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.99.0.3/32")},
		},
	}}}
	link := &fakeLink{log: log}
	res, err := (&Applier{Link: link, Device: dev, Iface: "wg0"}).
		Apply(targetFor(priv, peerFrom(add, "10.99.0.2/32", 25)))
	if err != nil {
		t.Fatal(err)
	}
	if res.Ops != 2 || dev.configure != 1 {
		t.Fatalf("операций %d, configure %d; ожидалось 2/1", res.Ops, dev.configure)
	}
	if got := strings.Join(log.calls, ","); got != "link,address,snapshot,configure" {
		t.Fatalf("порядок вызовов %q; ожидался link,address,snapshot,configure", got)
	}
	if dev.last.ReplacePeers {
		t.Fatal("ReplacePeers должен оставаться false")
	}
	if len(dev.last.Peers) != 2 {
		t.Fatalf("пиров в конфигурации %d; ожидалось 2", len(dev.last.Peers))
	}
	removed := 0
	for _, p := range dev.last.Peers {
		if p.Remove {
			removed++
		}
	}
	if removed != 1 {
		t.Fatalf("снятых пиров %d; ожидался 1", removed)
	}
}

func TestApplyStopsBeforeKernelWhenLinkFails(t *testing.T) {
	dev := &fakeDevice{}
	link := &fakeLink{failLink: true}
	_, err := (&Applier{Link: link, Device: dev, Iface: "wg0"}).
		Apply(targetFor(newKey(t)))
	if err == nil {
		t.Fatal("отказ интерфейса проигнорирован")
	}
	if link.addrs != 0 || dev.snapshots != 0 || dev.configure != 0 {
		t.Fatalf("адресов %d, снимков %d, configure %d; ожидалось 0/0/0", link.addrs, dev.snapshots, dev.configure)
	}
}

func TestApplyStopsOnAddressFailure(t *testing.T) {
	dev := &fakeDevice{}
	_, err := (&Applier{Link: &fakeLink{failAddr: true}, Device: dev, Iface: "wg0"}).
		Apply(targetFor(newKey(t)))
	if err == nil {
		t.Fatal("отказ адреса проигнорирован")
	}
	if dev.snapshots != 0 || dev.configure != 0 {
		t.Fatalf("снимков %d, configure %d; ожидалось 0/0", dev.snapshots, dev.configure)
	}
}

func TestApplyStopsOnSnapshotFailure(t *testing.T) {
	dev := &fakeDevice{failSnapshot: true}
	res, err := (&Applier{Link: &fakeLink{}, Device: dev, Iface: "wg0"}).
		Apply(targetFor(newKey(t)))
	if err == nil {
		t.Fatal("отказ снимка проигнорирован")
	}
	if dev.configure != 0 || res.Ops != 0 {
		t.Fatalf("configure %d, операций %d; ожидалось 0/0", dev.configure, res.Ops)
	}
}

func TestApplyStopsOnDiffFailure(t *testing.T) {
	priv := newKey(t)
	peer := newKey(t)
	dev := &fakeDevice{}
	dup := peerFrom(peer, "10.99.0.2/32", 25)
	_, err := (&Applier{Link: &fakeLink{}, Device: dev, Iface: "wg0"}).
		Apply(targetFor(priv, dup, dup))
	if err == nil {
		t.Fatal("повтор ключа в целевом наборе проигнорирован")
	}
	if !errors.Is(err, ErrDuplicatePeer) {
		t.Fatalf("ожидалась ErrDuplicatePeer, получено %v", err)
	}
	if dev.configure != 0 {
		t.Fatal("configure вызван после ошибки дельты")
	}
}

func TestApplyStopsOnConfigFailure(t *testing.T) {
	priv := newKey(t)
	peer := newKey(t)
	dev := &fakeDevice{}
	bad := targetFor(priv, peerFrom(peer, "10.99.0.2/32", 25))
	bad.PrivateKey = "не-ключ"
	_, err := (&Applier{Link: &fakeLink{}, Device: dev, Iface: "wg0"}).Apply(bad)
	if err == nil {
		t.Fatal("неверный приватный ключ проигнорирован")
	}
	if dev.configure != 0 {
		t.Fatal("configure вызван после ошибки конфигурации")
	}
}

func TestApplyReportsConfigureFailureWithBefore(t *testing.T) {
	priv := newKey(t)
	peer := newKey(t)
	target := targetFor(priv, peerFrom(peer, "10.99.0.2/32", 25))
	dev := &fakeDevice{
		state: LiveState{Peers: map[string]PeerState{
			peer.PublicKey().String(): {
				PublicKey:  peer.PublicKey().String(),
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32")},
			},
		}},
		failConfigure: true,
	}
	res, err := (&Applier{Link: &fakeLink{}, Device: dev, Iface: "wg0"}).Apply(target)
	if err == nil {
		t.Fatal("отказ configure проигнорирован")
	}
	if res.Ops != 1 || res.Before.Peers == nil {
		t.Fatalf("операций %d, снимок %v; ожидался 1 и непустой Before", res.Ops, res.Before.Peers)
	}
}

func TestApplyRejectsBrokenKeyWithEmptyDelta(t *testing.T) {
	priv := newKey(t)
	peer := newKey(t)
	target := targetFor(priv, peerFrom(peer, "10.99.0.2/32", 25))
	target.PrivateKey = "не-ключ"
	dev := &fakeDevice{state: LiveState{Peers: map[string]PeerState{
		peer.PublicKey().String(): {
			PublicKey:    peer.PublicKey().String(),
			AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32")},
			KeepaliveSec: 25,
		},
	}}}
	ops, err := Diff(dev.state, target.Peers)
	if err != nil || len(ops) != 0 {
		t.Fatalf("предусловие нарушено: дельта %d операций, ошибка %v", len(ops), err)
	}
	res, err := (&Applier{Link: &fakeLink{}, Device: dev, Iface: "wg0"}).Apply(target)
	if err == nil {
		t.Fatal("неверный ключ принят при пустой дельте")
	}
	if dev.configure != 0 || res.Ops != 0 {
		t.Fatalf("configure %d, операций %d; ожидалось 0/0", dev.configure, res.Ops)
	}
}

func TestApplyConfiguresDeviceWithEmptyPeerDelta(t *testing.T) {
	for _, name := range []string{"initial-empty", "port", "key"} {
		t.Run(name, func(t *testing.T) {
			priv := newKey(t)
			target := targetFor(priv)
			before := LiveState{PublicKey: priv.PublicKey().String(), ListenPort: 51820, IfaceRxBytes: 123, IfaceTxBytes: 456}
			switch name {
			case "initial-empty":
				before.PublicKey, before.ListenPort = "", 0
			case "port", "key":
				peer := peerFrom(newKey(t), "10.99.0.2/32", 25)
				target.Peers = []TargetPeer{peer}
				before.Peers = map[string]PeerState{peer.PublicKey: {PublicKey: peer.PublicKey, AllowedIPs: peer.AllowedIPs, KeepaliveSec: 25}}
				if name == "port" {
					before.ListenPort = 51821
				} else {
					before.PublicKey = newKey(t).PublicKey().String()
				}
			}
			dev := &fakeDevice{state: before}
			res, err := (&Applier{Link: &fakeLink{}, Device: dev, Iface: "wg0"}).Apply(target)
			if err != nil || dev.configure != 1 {
				t.Fatal("параметры устройства не применены при пустой дельте")
			}
			if res.Ops != 0 || !reflect.DeepEqual(res.Before, before) || len(dev.last.Peers) != 0 || dev.last.ReplacePeers {
				t.Fatal("пустая дельта изменила пиеров или снимок")
			}
			if dev.last.PrivateKey == nil || *dev.last.PrivateKey != priv || dev.last.ListenPort == nil || *dev.last.ListenPort != 51820 {
				t.Fatal("неверные параметры устройства")
			}
		})
	}
}

func TestApplierSnapshotDelegatesWithoutChanges(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			before := LiveState{PublicKey: newKey(t).PublicKey().String(), ListenPort: 51820, IfaceRxBytes: 31, IfaceTxBytes: 47,
				Peers: map[string]PeerState{"peer": {PublicKey: "peer", RxBytes: 11, TxBytes: 17}}}
			dev := &fakeDevice{state: before, failSnapshot: fail}
			link := &fakeLink{}
			a := &Applier{Link: link, Device: dev, Iface: "wg-test"}
			snapshotter, ok := any(a).(interface{ Snapshot() (LiveState, error) })
			if !ok {
				t.Fatal("Applier не предоставляет Snapshot")
			}
			got, err := snapshotter.Snapshot()
			if fail {
				if !errors.Is(err, errTest) || !reflect.DeepEqual(got, LiveState{}) {
					t.Fatal("ошибка снимка потеряна")
				}
			} else if err != nil || !reflect.DeepEqual(got, before) {
				t.Fatal("снимок изменён при делегировании")
			}
			if dev.snapshotIface != "wg-test" || dev.snapshots != 1 || dev.configure != 0 || link.links != 0 || link.addrs != 0 {
				t.Fatal("снимок вызвал изменения или использовал другое имя интерфейса")
			}
		})
	}
}
