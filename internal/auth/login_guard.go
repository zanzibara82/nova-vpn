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

// loginStore — ровно те команды Redis, которые нужны счётчикам: интерфейс позволяет
// проверить прогрессию и две оси без живого Redis.
type loginStore interface {
	Incr(ctx context.Context, key string) *redis.IntCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
}

// LoginGuard — прогрессивная задержка ответа на неудачный вход (спецификация §2, §5.2).
// Счётчик живёт в Redis, а не в памяти процесса: экземпляров API несколько, и
// «прогрессивность» обязана переживать рестарт.
type LoginGuard struct {
	rdb loginStore
	log *slog.Logger
}

func NewLoginGuard(rdb *redis.Client, log *slog.Logger) *LoginGuard {
	if rdb == nil {
		return &LoginGuard{log: log}
	}
	return &LoginGuard{rdb: rdb, log: log}
}

// Две оси, как требует §5.2: «по IP и по аккаунту». Пара email+ip — третье
// измерение: перебор одного аккаунта с сотни адресов или сотни аккаунтов с одного
// адреса получал бы свежий счётчик на каждую попытку. В ключ идёт только хэш, чтобы
// журнал Redis не читался как список адресов и аккаунтов.
func accountKey(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return "loginfail:acct:" + hex.EncodeToString(sum[:])
}

func ipKey(ip string) string {
	sum := sha256.Sum256([]byte(ip))
	return "loginfail:ip:" + hex.EncodeToString(sum[:])
}

func delayFor(n int64) time.Duration {
	shift := n - 1
	if shift < 0 {
		shift = 0
	}
	if shift > failMaxShift {
		shift = failMaxShift
	}
	return failBaseDelay << shift
}

// bump увеличивает счётчик оси и ставит окно на первой неудаче. Ошибка Redis —
// fail-open для этой оси: недоступность хранилища не должна запирать вход.
func (g *LoginGuard) bump(ctx context.Context, key string) time.Duration {
	n, err := g.rdb.Incr(ctx, key).Result()
	if err != nil {
		g.log.Warn("login guard unavailable, failing open", "axis", key, "err", err)
		return 0
	}
	if n == 1 {
		if err := g.rdb.Expire(ctx, key, failWindow).Err(); err != nil {
			g.log.Warn("login guard window", "err", err)
		}
	}
	return delayFor(n)
}

// Delay фиксирует неудачу и возвращает паузу: 250, 500, 1000, 2000, 4000 мс, дальше —
// 4000 мс. Возвращается Duration, а не происходит sleep: хендлер решает сам, слушать ли
// контекст запроса.
func (g *LoginGuard) Delay(ctx context.Context, email, ip string) time.Duration {
	if g.rdb == nil {
		return 0
	}
	acct := g.bump(ctx, accountKey(email))
	byIP := g.bump(ctx, ipKey(ip))
	if byIP > acct {
		return byIP
	}
	return acct
}

func (g *LoginGuard) Reset(ctx context.Context, email, ip string) {
	if g.rdb == nil {
		return
	}
	if err := g.rdb.Del(ctx, accountKey(email), ipKey(ip)).Err(); err != nil {
		g.log.Warn("login guard reset", "err", err)
	}
}
