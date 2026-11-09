package wg

import (
	"bytes"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func configPrivateKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal("не удалось сгенерировать тестовый ключ")
	}
	return key
}

func TestConfigForNeverReplacesPeers(t *testing.T) {
	key := configPrivateKey(t)
	pub := configPrivateKey(t).PublicKey().String()
	target := Target{
		PrivateKey: key.String(), ListenPort: 51820, MTU: 1420,
		TunnelAddress: netip.MustParsePrefix("10.99.0.1/24"),
		Peers:         []TargetPeer{{PublicKey: pub, State: StateActive}},
	}
	available := []Op{
		{Kind: OpAdd, PublicKey: pub},
		{Kind: OpUpdate, PublicKey: pub},
		{Kind: OpRemove, PublicKey: pub},
	}
	for subset := 0; subset < 1<<len(available); subset++ {
		var ops []Op
		for i, op := range available {
			if subset&(1<<i) != 0 {
				ops = append(ops, op)
			}
		}
		cfg, err := ConfigFor(target, ops)
		if err != nil {
			t.Fatal("не удалось собрать конфигурацию")
		}
		if cfg.ReplacePeers {
			t.Fatalf("набор операций %d включает полную замену пиров", subset)
		}
		if cfg.PrivateKey == nil || *cfg.PrivateKey != key {
			t.Fatal("приватный ключ не сохранён")
		}
		if cfg.ListenPort == nil || *cfg.ListenPort != 51820 {
			t.Fatal("порт прослушивания не сохранён")
		}
		if len(cfg.Peers) != len(ops) {
			t.Fatal("конфигурация должна содержать только переданные операции")
		}
		if cfg.FirewallMark != nil {
			t.Fatal("марка пакетов не должна изменяться")
		}
	}
}

func TestConfigForMapsOperations(t *testing.T) {
	addKey := configPrivateKey(t).PublicKey()
	updateKey := configPrivateKey(t).PublicKey()
	removeKey := configPrivateKey(t).PublicKey()
	ops := []Op{
		{Kind: OpAdd, PublicKey: addKey.String(), AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("10.99.0.2/32"),
			netip.MustParsePrefix("2001:db8::7/64"),
		}, KeepaliveSec: 25},
		{Kind: OpUpdate, PublicKey: updateKey.String(), AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("10.99.0.7/24"),
			netip.MustParsePrefix("2001:db8::8/128"),
		}, KeepaliveSec: 0},
		{Kind: OpRemove, PublicKey: removeKey.String(), AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("10.99.0.4/32"),
		}, KeepaliveSec: 30},
	}
	cfg, err := ConfigFor(Target{PrivateKey: configPrivateKey(t).String()}, ops)
	if err != nil {
		t.Fatal("не удалось собрать конфигурацию")
	}
	if cfg.ReplacePeers || len(cfg.Peers) != 3 {
		t.Fatal("нарушен состав дельты пиров")
	}
	if cfg.ListenPort == nil || *cfg.ListenPort != 0 {
		t.Fatal("нулевой порт должен передаваться явно")
	}
	keepalive := 25 * time.Second
	zero := time.Duration(0)
	want := []wgtypes.PeerConfig{
		{PublicKey: addKey, ReplaceAllowedIPs: true, PersistentKeepaliveInterval: &keepalive, AllowedIPs: []net.IPNet{
			{IP: net.ParseIP("10.99.0.2").To4(), Mask: net.CIDRMask(32, 32)},
			{IP: net.ParseIP("2001:db8::7"), Mask: net.CIDRMask(64, 128)},
		}},
		{PublicKey: updateKey, ReplaceAllowedIPs: true, PersistentKeepaliveInterval: &zero, AllowedIPs: []net.IPNet{
			{IP: net.ParseIP("10.99.0.7").To4(), Mask: net.CIDRMask(24, 32)},
			{IP: net.ParseIP("2001:db8::8"), Mask: net.CIDRMask(128, 128)},
		}},
		{PublicKey: removeKey, Remove: true},
	}
	if !reflect.DeepEqual(cfg.Peers, want) {
		t.Fatal("поля операций или порядок пиров не соответствуют ожидаемым")
	}
	cfg.Peers[0].AllowedIPs[0].IP[0] = 192
	if ops[0].AllowedIPs[0] != netip.MustParsePrefix("10.99.0.2/32") {
		t.Fatal("конфигурация изменяет входные адреса")
	}
}

func TestConfigForExplicitKeepalive(t *testing.T) {
	for _, kind := range []OpKind{OpAdd, OpUpdate} {
		for _, seconds := range []int{0, 25} {
			cfg, err := ConfigFor(Target{PrivateKey: configPrivateKey(t).String()}, []Op{{
				Kind: kind, PublicKey: configPrivateKey(t).PublicKey().String(), KeepaliveSec: seconds,
			}})
			if err != nil || len(cfg.Peers) != 1 {
				t.Fatal("не удалось собрать операцию")
			}
			interval := cfg.Peers[0].PersistentKeepaliveInterval
			if interval == nil || *interval != time.Duration(seconds)*time.Second {
				t.Fatalf("операция %s не передаёт keepalive %d с явно", kind, seconds)
			}
		}
	}
}

func TestConfigForClearsOldKeyAddressesAfterRotation(t *testing.T) {
	oldKey := configPrivateKey(t).PublicKey().String()
	newKey := configPrivateKey(t).PublicKey().String()
	address := []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32")}
	target := Target{
		PrivateKey: configPrivateKey(t).String(),
		Peers: []TargetPeer{
			{PublicKey: oldKey, AllowedIPs: address, KeepaliveSec: 25, State: StateRotatingOldKey},
			{PublicKey: newKey, AllowedIPs: address, KeepaliveSec: 25, State: StateActive},
		},
	}
	ops, err := Diff(LiveState{Peers: map[string]PeerState{
		oldKey: {PublicKey: oldKey, AllowedIPs: address, KeepaliveSec: 25},
	}}, target.Peers)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ConfigFor(target, ops)
	if err != nil || len(cfg.Peers) != 2 || cfg.ReplacePeers {
		t.Fatal("не удалось собрать дельту ротации")
	}
	for _, peer := range cfg.Peers {
		if peer.Remove || !peer.ReplaceAllowedIPs {
			t.Fatal("ротация должна заменить адреса, не удаляя старый ключ")
		}
		switch peer.PublicKey.String() {
		case oldKey:
			if len(peer.AllowedIPs) != 0 {
				t.Fatal("адрес старого ключа не очищен")
			}
		case newKey:
			if len(peer.AllowedIPs) != 1 || !peer.AllowedIPs[0].IP.Equal(net.ParseIP("10.99.0.2")) ||
				!bytes.Equal(peer.AllowedIPs[0].Mask, net.CIDRMask(32, 32)) {
				t.Fatal("адрес не передан новому ключу")
			}
		default:
			t.Fatal("в ротации появился посторонний ключ")
		}
	}
}

func TestConfigForRejectsBrokenPrivateKeyWithoutDisclosure(t *testing.T) {
	for _, broken := range []string{"", "not-a-key", "AQ==", configPrivateKey(t).String() + "!"} {
		cfg, err := ConfigFor(Target{PrivateKey: broken}, nil)
		if err == nil {
			t.Fatal("неверный приватный ключ принят")
		}
		if !strings.Contains(err.Error(), "приватный ключ") {
			t.Fatal("ошибка приватного ключа должна иметь русский контекст")
		}
		if broken != "" && strings.Contains(err.Error(), broken) {
			t.Fatal("ошибка раскрывает входной приватный ключ")
		}
		if !reflect.DeepEqual(cfg, wgtypes.Config{}) {
			t.Fatal("ошибка должна возвращать пустую конфигурацию")
		}
	}
}

func TestConfigForRejectsBrokenPeerKeyWithoutPartialConfig(t *testing.T) {
	key := configPrivateKey(t)
	for _, kind := range []OpKind{OpAdd, OpUpdate, OpRemove} {
		for _, broken := range []string{"", "not-a-key", "AQ=="} {
			cfg, err := ConfigFor(Target{PrivateKey: key.String()}, []Op{
				{Kind: OpAdd, PublicKey: key.PublicKey().String()},
				{Kind: kind, PublicKey: broken},
			})
			if err == nil || !strings.Contains(err.Error(), "публичный ключ") {
				t.Fatal("неверный ключ пира должен отклоняться с русским контекстом")
			}
			if !reflect.DeepEqual(cfg, wgtypes.Config{}) {
				t.Fatal("ошибка ключа пира оставляет частичную конфигурацию")
			}
		}
	}
}

func TestConfigForRejectsUnknownOperationWithoutPartialConfig(t *testing.T) {
	key := configPrivateKey(t)
	for _, kind := range []OpKind{"", "unsupported"} {
		cfg, err := ConfigFor(Target{PrivateKey: key.String()}, []Op{
			{Kind: OpAdd, PublicKey: key.PublicKey().String()},
			{Kind: kind, PublicKey: key.PublicKey().String()},
		})
		if err == nil || !strings.Contains(err.Error(), "неизвестная операция") {
			t.Fatal("неизвестная операция должна отклоняться с русским контекстом")
		}
		if !reflect.DeepEqual(cfg, wgtypes.Config{}) {
			t.Fatal("неизвестная операция оставляет частичную конфигурацию")
		}
	}
}
