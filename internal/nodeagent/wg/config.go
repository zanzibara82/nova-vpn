package wg

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Target struct {
	PrivateKey    string
	ListenPort    int
	MTU           int
	TunnelAddress netip.Prefix
	Peers         []TargetPeer
}

// ConfigFor запрещает полную замену пиров ради сохранения handshake и счётчиков (ADR-004).
func ConfigFor(t Target, ops []Op) (wgtypes.Config, error) {
	key, err := wgtypes.ParseKey(t.PrivateKey)
	if err != nil {
		// Ошибка библиотеки может содержать исходный ключ.
		return wgtypes.Config{}, errors.New("wg: неверный приватный ключ")
	}
	port := t.ListenPort
	cfg := wgtypes.Config{
		PrivateKey:   &key,
		ListenPort:   &port,
		ReplacePeers: false,
		Peers:        make([]wgtypes.PeerConfig, 0, len(ops)),
	}
	for _, op := range ops {
		pub, err := wgtypes.ParseKey(op.PublicKey)
		if err != nil {
			return wgtypes.Config{}, errors.New("wg: неверный публичный ключ пира")
		}
		peer := wgtypes.PeerConfig{PublicKey: pub}
		switch op.Kind {
		case OpRemove:
			peer.Remove = true
		case OpAdd, OpUpdate:
			peer.ReplaceAllowedIPs = true
			peer.AllowedIPs = toIPNets(op.AllowedIPs)
			keepalive := time.Duration(op.KeepaliveSec) * time.Second
			peer.PersistentKeepaliveInterval = &keepalive
		default:
			return wgtypes.Config{}, fmt.Errorf("wg: неизвестная операция %q", op.Kind)
		}
		cfg.Peers = append(cfg.Peers, peer)
	}
	return cfg, nil
}

func toIPNets(prefixes []netip.Prefix) []net.IPNet {
	out := make([]net.IPNet, len(prefixes))
	for i, prefix := range prefixes {
		out[i] = net.IPNet{
			IP:   net.IP(prefix.Addr().AsSlice()),
			Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
		}
	}
	return out
}
