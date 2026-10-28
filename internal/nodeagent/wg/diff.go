package wg

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

type PeerState struct {
	PublicKey     string
	AllowedIPs    []netip.Prefix
	KeepaliveSec  int
	RxBytes       int64
	TxBytes       int64
	LastHandshake time.Time
}

type LiveState struct {
	PublicKey    string
	ListenPort   int
	IfaceRxBytes int64
	IfaceTxBytes int64
	Peers        map[string]PeerState
}

type PeerKind string

const (
	StateActive         PeerKind = "active"
	StateRotatingOldKey PeerKind = "rotating_old_key"
)

type TargetPeer struct {
	PublicKey    string
	AllowedIPs   []netip.Prefix
	KeepaliveSec int
	State        PeerKind
}

type OpKind string

const (
	OpAdd    OpKind = "add"
	OpUpdate OpKind = "update"
	OpRemove OpKind = "remove"
)

type Op struct {
	Kind         OpKind
	PublicKey    string
	AllowedIPs   []netip.Prefix
	KeepaliveSec int
}

var (
	ErrDuplicatePeer    = errors.New("wg: повтор публичного ключа в целевом наборе")
	ErrDuplicateAddress = errors.New("wg: два пира одного вида претендуют на один адрес")
	ErrUnknownPeerState = errors.New("wg: неизвестное состояние пира")
)

// Diff не сравнивает endpoint: его нет в целевом наборе, он обновляется ядром.
func Diff(live LiveState, target []TargetPeer) ([]Op, error) {
	entries := make([]TargetPeer, 0, len(target))
	seen := make(map[string]bool, len(target))
	for _, peer := range target {
		peer.PublicKey = strings.TrimSpace(peer.PublicKey)
		if peer.PublicKey == "" {
			return nil, errors.New("wg: пустой публичный ключ в целевом наборе")
		}
		if seen[peer.PublicKey] {
			return nil, fmt.Errorf("%w: %s", ErrDuplicatePeer, peer.PublicKey)
		}
		if peer.State != StateActive && peer.State != StateRotatingOldKey {
			return nil, fmt.Errorf("%w: %q", ErrUnknownPeerState, peer.State)
		}
		seen[peer.PublicKey] = true
		peer.AllowedIPs = normalizedPrefixes(peer.AllowedIPs)
		entries = append(entries, peer)
	}

	type claim struct {
		prefix netip.Prefix
		kind   PeerKind
	}
	claims := make(map[claim]string)
	owner := make(map[netip.Prefix]string)
	for _, peer := range entries {
		for _, prefix := range peer.AllowedIPs {
			c := claim{prefix: prefix, kind: peer.State}
			// Претендентов учитываем отдельно: победа active не должна скрыть двух старых ключей.
			if previous, exists := claims[c]; exists {
				return nil, fmt.Errorf("%w: %s, ключи %s и %s", ErrDuplicateAddress, prefix, previous, peer.PublicKey)
			}
			claims[c] = peer.PublicKey
			if owner[prefix] == "" || peer.State == StateActive {
				owner[prefix] = peer.PublicKey
			}
		}
	}

	effective := make(map[string][]netip.Prefix, len(entries))
	for prefix, key := range owner {
		effective[key] = append(effective[key], prefix)
	}
	for key := range effective {
		slices.SortFunc(effective[key], comparePrefixes)
	}

	ops := make([]Op, 0, len(entries))
	for _, peer := range entries {
		current, exists := live.Peers[peer.PublicKey]
		kind := OpAdd
		if exists {
			if current.KeepaliveSec == peer.KeepaliveSec &&
				slices.Equal(normalizedPrefixes(current.AllowedIPs), effective[peer.PublicKey]) {
				continue
			}
			kind = OpUpdate
		}
		ops = append(ops, Op{
			Kind: kind, PublicKey: peer.PublicKey,
			AllowedIPs: effective[peer.PublicKey], KeepaliveSec: peer.KeepaliveSec,
		})
	}
	for key := range live.Peers {
		if !seen[key] {
			ops = append(ops, Op{Kind: OpRemove, PublicKey: key})
		}
	}
	slices.SortFunc(ops, func(a, b Op) int {
		if order := cmp.Compare(a.PublicKey, b.PublicKey); order != 0 {
			return order
		}
		return cmp.Compare(a.Kind, b.Kind)
	})
	return ops, nil
}

func normalizedPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, len(prefixes))
	for i, prefix := range prefixes {
		out[i] = prefix.Masked()
	}
	slices.SortFunc(out, comparePrefixes)
	return slices.Compact(out)
}

func comparePrefixes(a, b netip.Prefix) int {
	return cmp.Compare(a.String(), b.String())
}
