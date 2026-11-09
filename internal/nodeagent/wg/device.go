package wg

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type DeviceClient interface {
	Snapshot(iface string) (LiveState, error)
	Configure(iface string, cfg wgtypes.Config) error
}

type WG struct{ c *wgctrl.Client }

func Open() (*WG, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wg: управляющий сокет: %w", err)
	}
	return &WG{c: c}, nil
}

func (w *WG) Close() error {
	if err := w.c.Close(); err != nil {
		return fmt.Errorf("wg: закрытие управляющего сокета: %w", err)
	}
	return nil
}

// Snapshot не возвращает частичный снимок: без обоих счётчиков применение приостанавливается (R5).
func (w *WG) Snapshot(iface string) (LiveState, error) {
	dev, err := w.c.Device(iface)
	if err != nil {
		return LiveState{}, fmt.Errorf("wg: устройство %s: %w", iface, err)
	}
	rx, err := readCounter("/sys/class/net/" + iface + "/statistics/rx_bytes")
	if err != nil {
		return LiveState{}, fmt.Errorf("wg: снимок %s: %w", iface, err)
	}
	tx, err := readCounter("/sys/class/net/" + iface + "/statistics/tx_bytes")
	if err != nil {
		return LiveState{}, fmt.Errorf("wg: снимок %s: %w", iface, err)
	}
	out := LiveState{
		PublicKey:    dev.PublicKey.String(),
		ListenPort:   dev.ListenPort,
		IfaceRxBytes: rx,
		IfaceTxBytes: tx,
		Peers:        make(map[string]PeerState, len(dev.Peers)),
	}
	for _, p := range dev.Peers {
		key := p.PublicKey.String()
		out.Peers[key] = PeerState{
			PublicKey:     key,
			AllowedIPs:    fromIPNets(p.AllowedIPs),
			KeepaliveSec:  int(p.PersistentKeepaliveInterval.Seconds()),
			RxBytes:       p.ReceiveBytes,
			TxBytes:       p.TransmitBytes,
			LastHandshake: p.LastHandshakeTime,
		}
	}
	return out, nil
}

func (w *WG) Configure(iface string, cfg wgtypes.Config) error {
	if err := w.c.ConfigureDevice(iface, cfg); err != nil {
		return fmt.Errorf("wg: настройка %s: %w", iface, err)
	}
	return nil
}

func fromIPNets(nets []net.IPNet) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(nets))
	for _, n := range nets {
		addr, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ones, bits := n.Mask.Size()
		if bits == 32 {
			addr = addr.Unmap()
		}
		if bits != addr.BitLen() {
			continue
		}
		out = append(out, netip.PrefixFrom(addr, ones).Masked())
	}
	return out
}

func readCounter(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("wg: чтение счётчика %s: %w", path, err)
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("wg: неверный счётчик %s: %w", path, err)
	}
	if v < 0 {
		return 0, fmt.Errorf("wg: отрицательный счётчик %s", path)
	}
	return v, nil
}
