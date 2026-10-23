package servers

import (
	"testing"
	"time"
)

func TestAvailableRequiresFreshOK(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	ok := "ok"
	fresh := now.Add(-30 * time.Second)
	stale := now.Add(-91 * time.Second)
	errStatus := "error"
	staleStatus := "stale"

	cases := []struct {
		name   string
		status *string
		at     *time.Time
		want   Availability
	}{
		{"нет строки health вообще", nil, nil, AvailabilityUnknown},
		{"health есть, но статус не пришёл", nil, &fresh, AvailabilityUnknown},
		{"heartbeat не был", &ok, nil, AvailabilityUnknown},
		{"ok свежий", &ok, &fresh, AvailabilityAvailable},
		{"ok на границе окна", &ok, &stale, AvailabilityUnknown},
		{"error", &errStatus, &fresh, AvailabilityUnknown},
		{"stale", &staleStatus, &fresh, AvailabilityUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Available(c.status, c.at, now); got != c.want {
				t.Errorf("Available = %q, want %q", got, c.want)
			}
		})
	}
}

func TestCatalogHasNoMeasuredNumbers(t *testing.T) {
	// Смысл теста — не формат, а обещание: latency_ms и load никогда не становятся
	// нулём и никогда не «правдоподобным числом» (спецификация §13.4, ADR-006).
	if s := (Summary{}); s.LatencyMS != nil || s.Load != nil {
		t.Fatal("latency/load должны быть nil по умолчанию")
	}
}
