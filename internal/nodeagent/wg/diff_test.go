package wg

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"
)

func prefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			t.Fatalf("разбор префикса %q: %v", value, err)
		}
		out = append(out, prefix)
	}
	return out
}

func assertOps(t *testing.T, got, want []Op) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("операции = %+v, ожидалось %+v", got, want)
	}
	for i := range want {
		if got[i].Kind != want[i].Kind || got[i].PublicKey != want[i].PublicKey ||
			got[i].KeepaliveSec != want[i].KeepaliveSec || !slices.Equal(got[i].AllowedIPs, want[i].AllowedIPs) {
			t.Fatalf("операция %d = %+v, ожидалось %+v", i, got[i], want[i])
		}
	}
}

func permutations[T any](values []T) [][]T {
	values = slices.Clone(values)
	var out [][]T
	var visit func(int)
	visit = func(start int) {
		if start == len(values) {
			out = append(out, slices.Clone(values))
			return
		}
		for i := start; i < len(values); i++ {
			values[start], values[i] = values[i], values[start]
			visit(start + 1)
			values[start], values[i] = values[i], values[start]
		}
	}
	visit(0)
	return out
}

func TestDiffUnchangedPeerProducesNoOperations(t *testing.T) {
	live := LiveState{
		PublicKey: "node", ListenPort: 51820, IfaceRxBytes: 120, IfaceTxBytes: 240,
		Peers: map[string]PeerState{
			"a": {
				PublicKey: "a", AllowedIPs: prefixes(t, "10.0.0.2/32", "10.0.0.0/24"), KeepaliveSec: 25,
				RxBytes: 100, TxBytes: 200, LastHandshake: time.Unix(1700000000, 0),
			},
		},
	}
	target := []TargetPeer{
		{PublicKey: "a", AllowedIPs: prefixes(t, "10.0.0.0/24", "10.0.0.2/32"), KeepaliveSec: 25, State: StateActive},
	}
	ops, err := Diff(live, target)
	if err != nil {
		t.Fatal(err)
	}
	assertOps(t, ops, nil)
}

func TestDiffReportsAddUpdateRemove(t *testing.T) {
	live := LiveState{Peers: map[string]PeerState{
		"keep":    {PublicKey: "keep", AllowedIPs: prefixes(t, "10.0.0.2/32"), KeepaliveSec: 25},
		"change":  {PublicKey: "change", AllowedIPs: prefixes(t, "10.0.0.3/32"), KeepaliveSec: 25},
		"removed": {PublicKey: "removed", AllowedIPs: prefixes(t, "10.0.0.4/32"), KeepaliveSec: 25},
	}}
	target := []TargetPeer{
		{PublicKey: "keep", AllowedIPs: prefixes(t, "10.0.0.2/32"), KeepaliveSec: 25, State: StateActive},
		{PublicKey: "change", AllowedIPs: prefixes(t, "10.0.0.3/32"), KeepaliveSec: 30, State: StateActive},
		{PublicKey: "added", AllowedIPs: prefixes(t, "10.0.0.5/32"), KeepaliveSec: 25, State: StateActive},
	}
	ops, err := Diff(live, target)
	if err != nil {
		t.Fatal(err)
	}
	assertOps(t, ops, []Op{
		{Kind: OpAdd, PublicKey: "added", AllowedIPs: prefixes(t, "10.0.0.5/32"), KeepaliveSec: 25},
		{Kind: OpUpdate, PublicKey: "change", AllowedIPs: prefixes(t, "10.0.0.3/32"), KeepaliveSec: 30},
		{Kind: OpRemove, PublicKey: "removed"},
	})
}

func TestDiffUpdatesChangedAddressWithSamePrefixCount(t *testing.T) {
	live := LiveState{Peers: map[string]PeerState{
		"a": {PublicKey: "a", AllowedIPs: prefixes(t, "10.0.0.2/32"), KeepaliveSec: 25},
	}}
	ops, err := Diff(live, []TargetPeer{
		{PublicKey: "a", AllowedIPs: prefixes(t, "10.0.0.3/32"), KeepaliveSec: 25, State: StateActive},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertOps(t, ops, []Op{
		{Kind: OpUpdate, PublicKey: "a", AllowedIPs: prefixes(t, "10.0.0.3/32"), KeepaliveSec: 25},
	})
}

func TestDiffTreatsAllowedIPsAsNormalizedSet(t *testing.T) {
	for _, kind := range []PeerKind{StateActive, StateRotatingOldKey} {
		t.Run(string(kind), func(t *testing.T) {
			target := []TargetPeer{{
				PublicKey: "a", State: kind,
				AllowedIPs: prefixes(t, "2001:db8::2/64", "10.0.0.7/24", "10.0.0.0/24", "2001:db8::/64"),
			}}
			ops, err := Diff(LiveState{}, target)
			if err != nil {
				t.Fatal(err)
			}
			assertOps(t, ops, []Op{{
				Kind: OpAdd, PublicKey: "a", AllowedIPs: prefixes(t, "10.0.0.0/24", "2001:db8::/64"),
			}})
			live := LiveState{Peers: map[string]PeerState{
				"a": {PublicKey: "a", AllowedIPs: prefixes(t, "2001:db8::/64", "10.0.0.9/24", "10.0.0.0/24")},
			}}
			ops, err = Diff(live, target)
			if err != nil {
				t.Fatal(err)
			}
			assertOps(t, ops, nil)
		})
	}
}

func TestDiffGivesSharedAddressToActiveKey(t *testing.T) {
	target := []TargetPeer{
		{PublicKey: "old", AllowedIPs: prefixes(t, "10.0.0.2/32", "10.0.0.2/32"), KeepaliveSec: 25, State: StateRotatingOldKey},
		{PublicKey: "new", AllowedIPs: prefixes(t, "10.0.0.2/32"), KeepaliveSec: 25, State: StateActive},
	}
	for i, desired := range permutations(target) {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			live := LiveState{Peers: map[string]PeerState{
				"old": {PublicKey: "old", AllowedIPs: prefixes(t, "10.0.0.2/32"), KeepaliveSec: 25},
			}}
			ops, err := Diff(live, desired)
			if err != nil {
				t.Fatal(err)
			}
			assertOps(t, ops, []Op{
				{Kind: OpAdd, PublicKey: "new", AllowedIPs: prefixes(t, "10.0.0.2/32"), KeepaliveSec: 25},
				{Kind: OpUpdate, PublicKey: "old", KeepaliveSec: 25},
			})
			live.Peers["old"] = PeerState{PublicKey: "old", KeepaliveSec: 25}
			live.Peers["new"] = PeerState{PublicKey: "new", AllowedIPs: prefixes(t, "10.0.0.2/32"), KeepaliveSec: 25}
			ops, err = Diff(live, desired)
			if err != nil {
				t.Fatal(err)
			}
			assertOps(t, ops, nil)
		})
	}
}

func TestDiffRetainsUnsharedPrefixesOnOldKey(t *testing.T) {
	target := []TargetPeer{
		{PublicKey: "old", AllowedIPs: prefixes(t, "10.0.0.7/24", "2001:db8::2/128"), State: StateRotatingOldKey},
		{PublicKey: "new", AllowedIPs: prefixes(t, "10.0.0.9/24"), State: StateActive},
	}
	for _, desired := range permutations(target) {
		ops, err := Diff(LiveState{}, desired)
		if err != nil {
			t.Fatal(err)
		}
		assertOps(t, ops, []Op{
			{Kind: OpAdd, PublicKey: "new", AllowedIPs: prefixes(t, "10.0.0.0/24")},
			{Kind: OpAdd, PublicKey: "old", AllowedIPs: prefixes(t, "2001:db8::2/128")},
		})
	}
}

func TestDiffRejectsDuplicateAndEmptyKeys(t *testing.T) {
	for _, key := range []string{"a", " a\t"} {
		ops, err := Diff(LiveState{}, []TargetPeer{
			{PublicKey: "a", State: StateActive}, {PublicKey: key, State: StateRotatingOldKey},
		})
		if !errors.Is(err, ErrDuplicatePeer) || len(ops) != 0 {
			t.Fatalf("ключ %q: операции = %+v, ошибка = %v; ожидалась ErrDuplicatePeer без операций", key, ops, err)
		}
	}
	for _, key := range []string{"", " \t\n"} {
		ops, err := Diff(LiveState{}, []TargetPeer{{PublicKey: key, State: StateActive}})
		if err == nil || len(ops) != 0 {
			t.Fatalf("пустой ключ: операции = %+v, ошибка = %v; ожидался отказ без операций", ops, err)
		}
	}
}

func TestDiffTrimsPublicKey(t *testing.T) {
	ops, err := Diff(LiveState{}, []TargetPeer{{PublicKey: " a\t", State: StateActive}})
	if err != nil {
		t.Fatal(err)
	}
	assertOps(t, ops, []Op{{Kind: OpAdd, PublicKey: "a"}})
}

func TestDiffRejectsTwoPeersOfOneKindOnOneAddress(t *testing.T) {
	for _, kinds := range [][]PeerKind{
		{StateActive, StateActive},
		{StateRotatingOldKey, StateRotatingOldKey},
		{StateActive, StateRotatingOldKey, StateRotatingOldKey},
		{StateRotatingOldKey, StateActive, StateActive},
	} {
		target := make([]TargetPeer, len(kinds))
		for i, kind := range kinds {
			target[i] = TargetPeer{
				PublicKey: fmt.Sprintf("key-%d", i), State: kind,
				AllowedIPs: prefixes(t, fmt.Sprintf("10.0.0.%d/24", i+1)),
			}
		}
		for i, desired := range permutations(target) {
			t.Run(fmt.Sprintf("%v/%d", kinds, i), func(t *testing.T) {
				ops, err := Diff(LiveState{}, desired)
				if !errors.Is(err, ErrDuplicateAddress) || len(ops) != 0 {
					t.Fatalf("операции = %+v, ошибка = %v; ожидалась ErrDuplicateAddress без операций", ops, err)
				}
			})
		}
	}
}

func TestDiffRejectsUnknownState(t *testing.T) {
	for _, state := range []PeerKind{"", "expired", "revoked"} {
		ops, err := Diff(LiveState{}, []TargetPeer{{PublicKey: "a", State: state}})
		if !errors.Is(err, ErrUnknownPeerState) || len(ops) != 0 {
			t.Fatalf("состояние %q: операции = %+v, ошибка = %v; ожидалась ErrUnknownPeerState без операций", state, ops, err)
		}
	}
}

func TestDiffEmptyTargetRemovesAllPeers(t *testing.T) {
	live := LiveState{Peers: map[string]PeerState{
		"z": {PublicKey: "z", AllowedIPs: prefixes(t, "10.0.0.2/32"), KeepaliveSec: 25},
		"a": {PublicKey: "a", AllowedIPs: prefixes(t, "10.0.0.3/32"), KeepaliveSec: 30},
	}}
	ops, err := Diff(live, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertOps(t, ops, []Op{{Kind: OpRemove, PublicKey: "a"}, {Kind: OpRemove, PublicKey: "z"}})
	ops, err = Diff(LiveState{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertOps(t, ops, nil)
}

func TestDiffEmptyAllowedIPsProduceNoUpdate(t *testing.T) {
	live := LiveState{Peers: map[string]PeerState{
		"a": {PublicKey: "a", AllowedIPs: []netip.Prefix{}},
		"b": {PublicKey: "b"},
	}}
	ops, err := Diff(live, []TargetPeer{
		{PublicKey: "a", State: StateRotatingOldKey},
		{PublicKey: "b", AllowedIPs: []netip.Prefix{}, State: StateActive},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertOps(t, ops, nil)
}

func TestDiffIsDeterministicAndDoesNotMutateInputs(t *testing.T) {
	target := []TargetPeer{
		{PublicKey: "z-added", AllowedIPs: prefixes(t, "2001:db8::7/64", "10.0.1.7/24", "10.0.1.0/24"), State: StateActive},
		{PublicKey: "a-update", AllowedIPs: prefixes(t, "10.0.0.7/24", "10.0.0.2/32"), KeepaliveSec: 30, State: StateActive},
		{PublicKey: "m-keep", State: StateActive},
	}
	current := []PeerState{
		{PublicKey: "a-update", AllowedIPs: prefixes(t, "10.0.0.9/24", "10.0.0.2/32"), KeepaliveSec: 25},
		{PublicKey: "m-keep"},
		{PublicKey: "c-remove", AllowedIPs: prefixes(t, "10.0.2.7/24"), KeepaliveSec: 25},
		{PublicKey: "b-remove", KeepaliveSec: 30},
	}
	want := []Op{
		{Kind: OpUpdate, PublicKey: "a-update", AllowedIPs: prefixes(t, "10.0.0.0/24", "10.0.0.2/32"), KeepaliveSec: 30},
		{Kind: OpRemove, PublicKey: "b-remove"},
		{Kind: OpRemove, PublicKey: "c-remove"},
		{Kind: OpAdd, PublicKey: "z-added", AllowedIPs: prefixes(t, "10.0.1.0/24", "2001:db8::/64")},
	}
	for _, desired := range permutations(target) {
		beforeTarget := slices.Clone(desired)
		for i := range beforeTarget {
			beforeTarget[i].AllowedIPs = slices.Clone(beforeTarget[i].AllowedIPs)
		}
		for _, peers := range permutations(current) {
			live := LiveState{Peers: make(map[string]PeerState)}
			beforeLive := LiveState{Peers: make(map[string]PeerState)}
			for _, peer := range peers {
				live.Peers[peer.PublicKey] = peer
				peer.AllowedIPs = slices.Clone(peer.AllowedIPs)
				beforeLive.Peers[peer.PublicKey] = peer
			}
			for range 8 {
				ops, err := Diff(live, desired)
				if err != nil {
					t.Fatal(err)
				}
				assertOps(t, ops, want)
				ops[0].AllowedIPs[0] = netip.MustParsePrefix("192.0.2.0/24")
				ops[3].AllowedIPs[0] = netip.MustParsePrefix("192.0.2.0/24")
				if !reflect.DeepEqual(live, beforeLive) || !reflect.DeepEqual(desired, beforeTarget) {
					t.Fatal("изменились входные данные или результат ссылается на входные срезы")
				}
			}
		}
	}
}
