package connections

import (
	"net/netip"
	"testing"
)

func TestNodeTunnelAddressIsFirstUsable(t *testing.T) {
	if got := NodeTunnelAddress(netip.MustParsePrefix("10.99.7.0/24")); got.String() != "10.99.7.1" {
		t.Errorf("NodeTunnelAddress = %v", got)
	}
	if got := NodeTunnelAddress(netip.MustParsePrefix("10.99.0.0/24")); got.String() != "10.99.0.1" {
		t.Errorf("пример спецификации §4.1 должен совпасть: %v", got)
	}
}

func TestPickAddressIsLowestFree(t *testing.T) {
	pool := netip.MustParsePrefix("10.99.7.0/28")
	busy := map[netip.Addr]bool{
		netip.MustParseAddr("10.99.7.1"): true, // узел всегда зарезервирован
		netip.MustParseAddr("10.99.7.2"): true,
	}
	got, err := PickAddress(pool, busy)
	if err != nil {
		t.Fatalf("PickAddress: %v", err)
	}
	if got.String() != "10.99.7.3" {
		t.Errorf("адрес = %v, want 10.99.7.3 (минимальный свободный)", got)
	}
}

func TestPickAddressExcludesNetworkAndBroadcast(t *testing.T) {
	// /30: 10.99.7.0 сеть, .1 узел, .2 — единственный клиент, .3 broadcast.
	pool := netip.MustParsePrefix("10.99.7.0/30")
	got, err := PickAddress(pool, map[netip.Addr]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "10.99.7.2" {
		t.Errorf("адрес = %v, want 10.99.7.2", got)
	}
	if _, err := PickAddress(pool, map[netip.Addr]bool{
		netip.MustParseAddr("10.99.7.2"): true,
	}); err != ErrPoolExhausted {
		t.Errorf("исчерпание пула: err = %v, want ErrPoolExhausted", err)
	}
}

func TestPickAddressRejectsNonIPv4Prefix(t *testing.T) {
	for _, p := range []string{"2001:db8::/64", "10.99.7.1/32"} {
		if _, err := PickAddress(netip.MustParsePrefix(p), nil); err == nil {
			t.Errorf("пул %s принят как пул клиентов", p)
		}
	}
}
