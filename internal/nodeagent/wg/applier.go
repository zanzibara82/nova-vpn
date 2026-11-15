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

// ApplyResult — что известно после вызова. Before это снимок ядра до изменений,
// он значим и при ошибке настройки. Ops — число операций дельты: при ошибке
// настройки ядро могло измениться, поэтому непустой Ops нельзя прочитать как
// «набор применён».
type ApplyResult struct {
	Before LiveState
	Ops    int
}

func (a *Applier) Snapshot() (LiveState, error) {
	return a.Device.Snapshot(a.Iface)
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
	// ConfigFor проверяет приватный ключ, поэтому вызывается и при пустой дельте:
	// иначе один и тот же Target принимался бы по-разному в зависимости от того,
	// совпали ли пиры, а ошибка ключа всплыла бы только на первом изменении.
	cfg, err := ConfigFor(t, ops)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("wg: применение: конфигурация: %w", err)
	}
	if len(ops) == 0 && before.PublicKey == cfg.PrivateKey.PublicKey().String() && before.ListenPort == *cfg.ListenPort {
		return ApplyResult{Before: before}, nil
	}
	if err := a.Device.Configure(a.Iface, cfg); err != nil {
		return ApplyResult{Before: before, Ops: len(ops)}, fmt.Errorf("wg: применение: настройка: %w", err)
	}
	return ApplyResult{Before: before, Ops: len(ops)}, nil
}
