package auth_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/novavpn/novavpn/internal/auth"
)

func redisOrNil(t *testing.T) *redis.Client {
	addr := os.Getenv("NOVAVPN_REDIS_ADDR")
	if addr == "" {
		t.Skip("NOVAVPN_REDIS_ADDR is not set; run `make up-dev` first")
	}
	c := redis.NewClient(&redis.Options{Addr: addr})
	if err := c.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("redis unreachable: %v", err)
	}
	return c
}

func TestDenylistAddAndContains(t *testing.T) {
	d := auth.NewRedisDenylist(redisOrNil(t), slog.New(slog.DiscardHandler))
	ctx := context.Background()
	jti := "jti-" + t.Name()
	if err := d.Add(ctx, jti, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	ok, err := d.Contains(ctx, jti)
	if err != nil || !ok {
		t.Fatalf("revoked jti not visible: ok=%v err=%v", ok, err)
	}
	miss, err := d.Contains(ctx, jti+"-never-added")
	if err != nil || miss {
		t.Fatalf("unknown jti reported as revoked: ok=%v err=%v", miss, err)
	}
}

func TestDenylistFailOpenOnDeadRedis(t *testing.T) {
	// Пустой список отзыва при отказе Redis — сознательный fail-open (спецификация
	// §4.3, §5.3): access-токен живёт не дольше 10 минут, и отзыв доступа делает
	// снятие пиера на узле, а не этот список.
	dead := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond})
	d := auth.NewRedisDenylist(dead, slog.New(slog.DiscardHandler))
	ok, err := d.Contains(context.Background(), "any")
	if ok {
		t.Fatal("fail-open must report not-revoked, not revoked")
	}
	if err == nil {
		t.Error("fail-open must surface the Redis error for the log")
	}
}
