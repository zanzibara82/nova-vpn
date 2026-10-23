package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	failWindow    = 15 * time.Minute
	failBaseDelay = 250 * time.Millisecond
	// Потолок 4 с: без него каждый отказ вешает горутину сервера на растущий срок,
	// и атака превращается в отказ по ресурсам.
	failMaxShift = 4
)

// LoginGuard — прогрессивная задержка ответа на неудачный вход (спецификация §2, §5.2).
// Счётчик живёт в Redis, а не в памяти процесса: экземпляров API несколько, и
// «прогрессивность» обязана переживать рестарт.
type LoginGuard struct {
	rdb *redis.Client
	log *slog.Logger
}

func NewLoginGuard(rdb *redis.Client, log *slog.Logger) *LoginGuard {
	return &LoginGuard{rdb: rdb, log: log}
}

// Ключ — хэш пары email+ip: email в ключ не кладётся в открытом виде, чтобы
// перебор не читался по журналу Redis, и чтобы длинный email не раздувал ключ.
func failKey(email, ip string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(email) + "|" + ip))
	return "loginfail:" + hex.EncodeToString(sum[:])
}

// Delay фиксирует неудачу и возвращает паузу: 250, 500, 1000, 2000, 4000 мс, дальше —
// 4000 мс. Возвращается Duration, а не происходит sleep: хендлер решает сам, слушать ли
// контекст запроса.
func (g *LoginGuard) Delay(ctx context.Context, email, ip string) time.Duration {
	if g.rdb == nil {
		return 0
	}
	key := failKey(email, ip)
	n, err := g.rdb.Incr(ctx, key).Result()
	if err != nil {
		g.log.Warn("login guard unavailable, failing open", "err", err)
		return 0
	}
	if n == 1 {
		if err := g.rdb.Expire(ctx, key, failWindow).Err(); err != nil {
			g.log.Warn("login guard window", "err", err)
		}
	}
	shift := n - 1
	if shift > failMaxShift {
		shift = failMaxShift
	}
	return failBaseDelay << shift
}

func (g *LoginGuard) Reset(ctx context.Context, email, ip string) {
	if g.rdb == nil {
		return
	}
	if err := g.rdb.Del(ctx, failKey(email, ip)).Err(); err != nil {
		g.log.Warn("login guard reset", "err", err)
	}
}
