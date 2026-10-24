package telemetry

import "time"

func Delta(lastRx, lastTx, curRx, curTx int64, haveBase bool) (rx, tx int64, reset bool) {
	switch {
	case !haveBase:
		return 0, 0, false
	case curRx < lastRx || curTx < lastTx:
		return 0, 0, true
	default:
		return curRx - lastRx, curTx - lastTx, false
	}
}

func DayOf(now time.Time) time.Time {
	y, m, d := now.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func CountHandshaked(peers []PeerStat, at time.Time, fresh time.Duration) int {
	n := 0
	for _, p := range peers {
		if p.LatestHandshake != nil && p.LatestHandshake.After(at.Add(-fresh)) && !p.LatestHandshake.After(at) {
			n++
		}
	}
	return n
}
