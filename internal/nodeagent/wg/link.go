package wg

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
)

type LinkManager interface {
	EnsureLink(name string, mtu int) error
	EnsureAddress(name string, addr netip.Prefix) error
}

type Netlink struct{}

var _ LinkManager = Netlink{}

func (Netlink) EnsureLink(name string, mtu int) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if !errors.As(err, &notFound) {
			return fmt.Errorf("wg: поиск интерфейса %q: %w", name, err)
		}
		link = &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name, MTU: mtu}}
		if err := netlink.LinkAdd(link); err != nil {
			return fmt.Errorf("wg: создание интерфейса %q: %w", name, err)
		}
	}
	if link.Type() != "wireguard" {
		return fmt.Errorf("wg: интерфейс %q имеет тип %q, ожидался wireguard", name, link.Type())
	}
	if link.Attrs().MTU != mtu {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("wg: установка MTU интерфейса %q: %w", name, err)
		}
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("wg: включение интерфейса %q: %w", name, err)
		}
	}
	return nil
}

func (Netlink) EnsureAddress(name string, addr netip.Prefix) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("wg: поиск интерфейса %q для адреса: %w", name, err)
	}
	if link.Type() != "wireguard" {
		return fmt.Errorf("wg: интерфейс %q имеет тип %q, ожидался wireguard", name, link.Type())
	}
	address, err := netlink.ParseAddr(addr.String())
	if err != nil {
		return fmt.Errorf("wg: разбор адреса интерфейса %q: %w", name, err)
	}
	if err := netlink.AddrReplace(link, address); err != nil {
		return fmt.Errorf("wg: назначение адреса интерфейса %q: %w", name, err)
	}
	return nil
}
