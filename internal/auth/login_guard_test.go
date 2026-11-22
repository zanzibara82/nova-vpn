package auth

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// fakeStore — минимальный Redis для проверки прогрессии и двух осей без живого
// сервера: те же команды, что использует LoginGuard.
type fakeStore struct {
	counts  map[string]int64
	expires map[string]time.Duration
}

func newFakeStore() *fakeStore {
	return &fakeStore{counts: map[string]int64{}, expires: map[string]time.Duration{}}
}

func (f *fakeStore) Incr(_ context.Context, key string) *redis.IntCmd {
	f.counts[key]++
	return redis.NewIntResult(f.counts[key], nil)
}

func (f *fakeStore) Expire(_ context.Context, key string, d time.Duration) *redis.BoolCmd {
	f.expires[key] = d
	return redis.NewBoolResult(true, nil)
}

func (f *fakeStore) Del(_ context.Context, keys ...string) *redis.IntCmd {
	var n int64
	for _, k := range keys {
		if _, ok := f.counts[k]; ok {
			delete(f.counts, k)
			n++
		}
	}
	return redis.NewIntResult(n, nil)
}

func newGuard(store *fakeStore) *LoginGuard {
	return &LoginGuard{rdb: store, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestDelayProgressesAndCaps(t *testing.T) {
	g := newGuard(newFakeStore())
	want := []time.Duration{
		250 * time.Millisecond, 500 * time.Millisecond, time.Second,
		2 * time.Second, 4 * time.Second, 4 * time.Second,
	}
	for i, w := range want {
		if got := g.Delay(context.Background(), "user@example.com", "203.0.113.7"); got != w {
			t.Fatalf("попытка %d: задержка = %v, want %v", i+1, got, w)
		}
	}
}

func TestDelayCountsAccountAndIPSeparately(t *testing.T) {
	ctx := context.Background()
	g := newGuard(newFakeStore())

	// Две неудачи одного аккаунта с одного адреса: обе оси на 2.
	g.Delay(ctx, "victim@example.com", "198.51.100.1")
	g.Delay(ctx, "victim@example.com", "198.51.100.1")

	// Тот же аккаунт с нового адреса идёт по оси аккаунта: третья неудача — 1000 мс,
	// а не свежие 250, которые дал бы ключ из пары email+ip.
	if got := g.Delay(ctx, "victim@example.com", "198.51.100.2"); got != time.Second {
		t.Errorf("аккаунт с нового IP: %v, want 1s", got)
	}
	// Другой аккаунт с уже «горячего» адреса идёт по оси IP (третья неудача адреса).
	if got := g.Delay(ctx, "other@example.com", "198.51.100.1"); got != time.Second {
		t.Errorf("новый аккаунт с горячего IP: %v, want 1s", got)
	}
}

func TestResetClearsBothAxes(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	g := newGuard(store)
	g.Delay(ctx, "user@example.com", "203.0.113.7")
	g.Delay(ctx, "user@example.com", "203.0.113.7")

	g.Reset(ctx, "user@example.com", "203.0.113.7")
	if got := g.Delay(ctx, "user@example.com", "203.0.113.7"); got != 250*time.Millisecond {
		t.Fatalf("после Reset задержка = %v, want 250ms", got)
	}
	// Ключи — хэши: адрес и аккаунт не должны читаться в журнале Redis.
	for k := range store.counts {
		if k == "loginfail:acct:user@example.com" || k == "loginfail:ip:203.0.113.7" {
			t.Errorf("ключ содержит исходные данные: %q", k)
		}
	}
}

func TestNilStoreFailsOpen(t *testing.T) {
	g := NewLoginGuard(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got := g.Delay(context.Background(), "a@example.com", "203.0.113.7"); got != 0 {
		t.Fatalf("без Redis задержка = %v, want 0", got)
	}
	g.Reset(context.Background(), "a@example.com", "203.0.113.7")
}
