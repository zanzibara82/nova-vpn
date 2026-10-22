//go:build integration

package httpx_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/novavpn/novavpn/internal/httpx"
)

func redisFromEnv(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("NOVAVPN_REDIS_ADDR")
	if addr == "" {
		t.Skip("NOVAVPN_REDIS_ADDR is not set; run `make up-dev` first")
	}
	c := redis.NewClient(&redis.Options{Addr: addr})
	if err := c.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("redis at %s unreachable: %v", addr, err)
	}
	return c
}

func TestTokenBucketAllowsBurstThenBlocks(t *testing.T) {
	ctx := context.Background()
	c := redisFromEnv(t)
	l := httpx.NewLimiter(c, slog.New(slog.DiscardHandler))
	key := "test:burst:" + time.Now().Format("150405.000000")

	for i := 0; i < 5; i++ {
		ok, _, err := l.Allow(ctx, key, 0.01, 5)
		if err != nil {
			t.Fatalf("Allow %d: %v", i, err)
		}
		if !ok {
			t.Fatalf("burst exhausted at %d/5", i)
		}
	}
	ok, retry, err := l.Allow(ctx, key, 0.01, 5)
	if err != nil {
		t.Fatalf("Allow after burst: %v", err)
	}
	if ok {
		t.Fatal("6th request allowed with burst=5")
	}
	if retry <= 0 {
		t.Errorf("retry_after = %v, want > 0", retry)
	}
}

func TestFailOpenWhenRedisGone(t *testing.T) {
	// Клиент наведён на несуществующий порт: поведение при отказе Redis — пустить
	// запрос и записать WARN, а не отказать (спецификация §4.3).
	dead := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond})
	l := httpx.NewLimiter(dead, slog.New(slog.DiscardHandler))
	ok, _, err := l.Allow(context.Background(), "test:dead", 1, 1)
	if !ok {
		t.Fatalf("fail-open must allow, got ok=%v err=%v", ok, err)
	}
	if err == nil {
		t.Error("fail-open must still report the Redis error for the log")
	}
}

func TestMiddlewareReturns429WithEnvelope(t *testing.T) {
	c := redisFromEnv(t)
	l := httpx.NewLimiter(c, slog.New(slog.DiscardHandler))
	name := "login:" + time.Now().Format("150405.000000")
	h := l.Middleware(name, 0.01, 1, func(*http.Request) string { return name })(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil))
	if w.Code != 200 {
		t.Fatalf("first request: %d", w.Code)
	}
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil))
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: %d, want 429", w2.Code)
	}
	if body := w2.Body.String(); !containsAll(body, `"code":"rate_limited"`, `"request_id"`) {
		t.Fatalf("429 body is not the documented envelope: %s", body)
	}
	if w2.Header().Get("Retry-After") == "" {
		t.Error("429 must carry Retry-After")
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
