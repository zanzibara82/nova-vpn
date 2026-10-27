package telemetry

import (
	"math"
	"testing"
	"time"
)

func TestDelta(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		lastRx, lastTx, curRx, curTx int64
		haveBase                     bool
		rx, tx                       int64
		reset                        bool
	}{
		{"нет основания", 0, 0, 180, 50, false, 0, 0, false},
		{"рост", 100, 50, 180, 50, true, 80, 0, false},
		{"рост обоих", 100, 50, 180, 90, true, 80, 40, false},
		{"сброс обоих", 100, 50, 10, 5, true, 0, 0, true},
		{"сброс rx", 100, 50, 10, 80, true, 0, 0, true},
		{"сброс tx", 100, 50, 180, 5, true, 0, 0, true},
		{"повтор", 100, 50, 100, 50, true, 0, 0, false},
		{"граница int64", math.MaxInt64 - 1, 0, math.MaxInt64, math.MaxInt64, true, 1, math.MaxInt64, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rx, tx, reset := Delta(tc.lastRx, tc.lastTx, tc.curRx, tc.curTx, tc.haveBase)
			if rx != tc.rx || tx != tc.tx || reset != tc.reset {
				t.Fatalf("дельта = (%d, %d, %v), ожидалась (%d, %d, %v)", rx, tx, reset, tc.rx, tc.tx, tc.reset)
			}
		})
	}
}

func TestDayOfUsesUTC(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"2026-10-24T16:30:00+05:00", "2026-10-24T00:00:00Z"},
		{"2026-10-24T11:30:00Z", "2026-10-24T00:00:00Z"},
		{"2026-10-24T01:30:00+05:00", "2026-10-23T00:00:00Z"},
		{"2026-10-24T23:30:00-03:00", "2026-10-25T00:00:00Z"},
	} {
		input, err := time.Parse(time.RFC3339, tc.input)
		if err != nil {
			t.Fatal(err)
		}
		got := DayOf(input)
		if got.Format(time.RFC3339) != tc.want || got.Location() != time.UTC {
			t.Fatalf("сутки %s: %v, ожидалось %s", tc.input, got, tc.want)
		}
	}
}

func TestCountHandshakedRequiresRecentPastObservation(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	fresh, old, boundary, future := now.Add(-time.Second), now.Add(-4*time.Minute), now.Add(-3*time.Minute), now.Add(time.Second)
	peers := []PeerStat{{LatestHandshake: &fresh}, {LatestHandshake: &old}, {}, {LatestHandshake: &boundary}, {LatestHandshake: &future}, {LatestHandshake: &now}}
	if got := CountHandshaked(peers, now, 3*time.Minute); got != 2 {
		t.Fatalf("свежих handshake = %d, ожидалось 2", got)
	}
	if got := CountHandshaked(nil, now, 3*time.Minute); got != 0 {
		t.Fatalf("пустой набор: %d", got)
	}
}
