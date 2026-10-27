package telemetry

import (
	"errors"
	"math"
	"testing"
)

// TestValidateObservedBounds — верхняя граница счётчиков проверяется до обращения к
// БД и Redis: дельта порядка max int64 переполняет bigint дневного агрегата, и
// транзакция откатывается уже после того, как пакет записан в Redis.
func TestValidateObservedBounds(t *testing.T) {
	report := func() ObservedReport {
		return ObservedReport{
			ConfigVersion: 1, InterfaceRxBytes: 1000, InterfaceTxBytes: 500,
			Peers: []PeerStat{{PublicKey: "k1", RxBytes: 1000, TxBytes: 500}},
		}
	}
	if err := validateObserved(report()); err != nil {
		t.Fatalf("корректный отчёт отвергнут: %v", err)
	}
	atLimit := report()
	atLimit.InterfaceRxBytes = MaxCounterBytes
	atLimit.InterfaceTxBytes = MaxCounterBytes
	atLimit.Peers[0].RxBytes = MaxCounterBytes
	atLimit.Peers[0].TxBytes = MaxCounterBytes
	if err := validateObserved(atLimit); err != nil {
		t.Fatalf("значение на границе отвергнуто: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*ObservedReport)
	}{
		{"интерфейсный rx выше границы", func(r *ObservedReport) { r.InterfaceRxBytes = MaxCounterBytes + 1 }},
		{"интерфейсный tx порядка max int64", func(r *ObservedReport) { r.InterfaceTxBytes = math.MaxInt64 }},
		{"rx пиера порядка max int64", func(r *ObservedReport) { r.Peers[0].RxBytes = math.MaxInt64 }},
		{"tx пиера выше границы", func(r *ObservedReport) { r.Peers[0].TxBytes = MaxCounterBytes + 1 }},
		{"rx пиера отрицателен", func(r *ObservedReport) { r.Peers[0].RxBytes = -1 }},
		{"версия отрицательна", func(r *ObservedReport) { r.ConfigVersion = -1 }},
		{"повтор ключа", func(r *ObservedReport) { r.Peers = append(r.Peers, r.Peers[0]) }},
		{"пиеров больше потолка", func(r *ObservedReport) { r.Peers = make([]PeerStat, MaxReportPeers+1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := report()
			tc.change(&rep)
			if err := validateObserved(rep); !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("отчёт принят: %v", err)
			}
		})
	}
}
