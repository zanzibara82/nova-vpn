package wg

import (
	"errors"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type fakeLink struct {
	links, addrs int
	failLink     bool
}

func (f *fakeLink) EnsureLink(string, int) error {
	f.links++
	if f.failLink {
		return errTest
	}
	return nil
}

func (f *fakeLink) EnsureAddress(string, netip.Prefix) error { f.addrs++; return nil }

type fakeDevice struct {
	state         LiveState
	snapshots     int
	configure     int
	last          wgtypes.Config
	failSnapshot  bool
	failConfigure bool
}

func (f *fakeDevice) Snapshot(string) (LiveState, error) {
	f.snapshots++
	if f.failSnapshot {
		return LiveState{}, errTest
	}
	return f.state, nil
}

func (f *fakeDevice) Configure(_ string, cfg wgtypes.Config) error {
	f.configure++
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
	dev := &fakeDevice{state: LiveState{Peers: map[string]PeerState{
		peer.PublicKey().String(): {
			PublicKey:    peer.PublicKey().String(),
			AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32")},
			KeepaliveSec: 25,
		},
	}}}
	link := &fakeLink{}
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
}

func TestApplyRemovesAndAdds(t *testing.T) {
	priv := newKey(t)
	add := newKey(t)
	drop := newKey(t)
	dev := &fakeDevice{state: LiveState{Peers: map[string]PeerState{
		drop.PublicKey().String(): {
			PublicKey:  drop.PublicKey().String(),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.99.0.3/32")},
		},
	}}}
	res, err := (&Applier{Link: &fakeLink{}, Device: dev, Iface: "wg0"}).
		Apply(targetFor(priv, peerFrom(add, "10.99.0.2/32", 25)))
	if err != nil {
		t.Fatal(err)
	}
	if res.Ops != 2 || dev.configure != 1 {
		t.Fatalf("операций %d, configure %d; ожидалось 2/1", res.Ops, dev.configure)
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
	_, err := (&Applier{Link: &fakeLink{failLink: true}, Device: dev, Iface: "wg0"}).
		Apply(targetFor(newKey(t)))
	if err == nil {
		t.Fatal("отказ интерфейса проигнорирован")
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
