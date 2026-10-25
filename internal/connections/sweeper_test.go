package connections

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

type fakeStore struct {
	expiredFn func(context.Context, time.Time) (int, error)
	dormantFn func(context.Context, time.Time) (int, error)
	staleFn   func(context.Context, time.Time) (int, error)
	retFn     func(context.Context, time.Time) (Retention, error)
	calls     []string
}

func (f *fakeStore) SweepExpired(ctx context.Context, now time.Time) (int, error) {
	f.calls = append(f.calls, "expired")
	if f.expiredFn == nil {
		return 0, nil
	}
	return f.expiredFn(ctx, now)
}

func (f *fakeStore) SweepDormant(ctx context.Context, now time.Time) (int, error) {
	f.calls = append(f.calls, "dormant")
	if f.dormantFn == nil {
		return 0, nil
	}
	return f.dormantFn(ctx, now)
}

func (f *fakeStore) SweepStale(ctx context.Context, now time.Time) (int, error) {
	f.calls = append(f.calls, "stale")
	if f.staleFn == nil {
		return 0, nil
	}
	return f.staleFn(ctx, now)
}

func (f *fakeStore) SweepRetention(ctx context.Context, now time.Time) (Retention, error) {
	f.calls = append(f.calls, "retention")
	if f.retFn == nil {
		return Retention{}, nil
	}
	return f.retFn(ctx, now)
}

func TestSweepAllRunsEveryKindDespiteErrors(t *testing.T) {
	boom := errors.New("boom")
	st := &fakeStore{
		expiredFn: func(context.Context, time.Time) (int, error) { return 0, boom },
		staleFn:   func(context.Context, time.Time) (int, error) { return 0, boom },
		dormantFn: func(_ context.Context, _ time.Time) (int, error) { return 3, nil },
		retFn: func(_ context.Context, _ time.Time) (Retention, error) {
			return Retention{EventsDeleted: 7}, nil
		},
	}
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))

	r := sweepAll(context.Background(), st, log, time.Unix(0, 0))
	if r.Dormant != 3 || r.Retention.EventsDeleted != 7 || r.Expired != 0 || r.Stale != 0 {
		t.Errorf("report = %+v", r)
	}
	if strings.Join(st.calls, ",") != "expired,dormant,stale,retention" {
		t.Errorf("kinds = %v, want all four in order", st.calls)
	}
	// Упавшие виды работы обязаны быть слышны, а не проглочены: ровно две Error-строки.
	if n := strings.Count(buf.String(), `"level":"ERROR"`); n != 2 {
		t.Errorf("journal has %d error lines, want 2 (%s)", n, buf.String())
	}
}
