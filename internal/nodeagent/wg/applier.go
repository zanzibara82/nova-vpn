package wg

import "fmt"

// Applier задаёт порядок шагов явно: интерфейс и адрес, снимок, дельта.
// Снимок обязан быть до Configure: пересоздание пиера обнуляет счётчики в ядре,
// и отчёт, снятый после применения, потерял бы байты (ADR-004, правило 4).
type Applier struct {
	Link   LinkManager
	Device DeviceClient
	Iface  string
}

type ApplyResult struct {
	Before LiveState
	Ops    int
}

func (a *Applier) Apply(t Target) (ApplyResult, error) {
	if err := a.Link.EnsureLink(a.Iface, t.MTU); err != nil {
		return ApplyResult{}, fmt.Errorf("wg: применение: интерфейс: %w", err)
	}
	if err := a.Link.EnsureAddress(a.Iface, t.TunnelAddress); err != nil {
		return ApplyResult{}, fmt.Errorf("wg: применение: адрес: %w", err)
	}
	before, err := a.Device.Snapshot(a.Iface)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("wg: применение: снимок: %w", err)
	}
	ops, err := Diff(before, t.Peers)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("wg: применение: дельта: %w", err)
	}
	if len(ops) == 0 {
		return ApplyResult{Before: before}, nil
	}
	cfg, err := ConfigFor(t, ops)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("wg: применение: конфигурация: %w", err)
	}
	if err := a.Device.Configure(a.Iface, cfg); err != nil {
		return ApplyResult{Before: before, Ops: len(ops)}, fmt.Errorf("wg: применение: настройка: %w", err)
	}
	return ApplyResult{Before: before, Ops: len(ops)}, nil
}
