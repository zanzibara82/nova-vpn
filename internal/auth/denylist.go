package auth

import (
	"context"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

type Denylist interface {
	Add(ctx context.Context, jti string, exp time.Time) error
	Contains(ctx context.Context, jti string) (bool, error)
}

type redisDenylist struct {
	rdb *redis.Client
	log *slog.Logger
}

func NewRedisDenylist(rdb *redis.Client, log *slog.Logger) Denylist {
	return &redisDenylist{rdb: rdb, log: log}
}

// Add пишет запись с TTL по exp: список не растёт бесконечно и не требует чистильщика.
func (d *redisDenylist) Add(ctx context.Context, jti string, exp time.Time) error {
	ttl := time.Until(exp)
	if ttl <= 0 {
		return nil // токен и так мёртв — записывать нечего
	}
	return d.rdb.Set(ctx, "deny:"+jti, "1", ttl).Err()
}

func (d *redisDenylist) Contains(ctx context.Context, jti string) (bool, error) {
	n, err := d.rdb.Exists(ctx, "deny:"+jti).Result()
	if err != nil {
		d.log.Warn("denylist unavailable, failing open", "err", err, "jti", jti)
		return false, err
	}
	return n > 0, nil
}
