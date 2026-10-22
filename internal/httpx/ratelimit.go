package httpx

import (
	"context"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// bucketLua — атомарный token bucket. Один EVAL на запрос, без WATCH-гонок:
// при 1,7 rps на desired-опрос это не узкое место, а корректность важнее.
const bucketLua = `
local rate  = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local now   = tonumber(ARGV[3])
local v = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(v[1])
local ts = tonumber(v[2])
if tokens == nil then tokens = burst end
if ts == nil then ts = now end
local elapsed = math.max(0, now - ts)
if rate > 0 then tokens = math.min(burst, tokens + elapsed * rate) end
local allowed = 0
local wait_ms = 0
if tokens >= 1 then allowed = 1; tokens = tokens - 1
elseif rate > 0 then wait_ms = math.ceil((1 - tokens) / rate * 1000) end
redis.call('HSET', KEYS[1], 'tokens', tostring(tokens), 'ts', tostring(now))
local ttl = 1000
if rate > 0 then ttl = math.ceil(burst / rate * 1000) end
redis.call('PEXPIRE', KEYS[1], ttl)
return {allowed, wait_ms}
`

type Limiter struct {
	rdb    *redis.Client
	log    *slog.Logger
	script *redis.Script
}

func NewLimiter(rdb *redis.Client, log *slog.Logger) *Limiter {
	return &Limiter{rdb: rdb, log: log, script: redis.NewScript(bucketLua)}
}

// Allow возвращает разрешение, задержку до следующего разрешения и исходную ошибку
// Redis. Вызов обязан смотреть на err даже когда allowed == true: fail-open должен быть
// виден в журнале.
func (l *Limiter) Allow(ctx context.Context, key string, rate float64, burst int) (bool, time.Duration, error) {
	now := float64(time.Now().UnixMilli())
	res, err := l.script.Run(ctx, l.rdb, []string{key}, rate, burst, now).Result()
	if err != nil {
		// Fail-open по спецификации §4.3.
		l.log.Warn("rate limiter unavailable, allowing request", "key", key, "err", err)
		return true, 0, err
	}
	arr, ok := res.([]any)
	if !ok || len(arr) != 2 {
		l.log.Warn("rate limiter returned garbage, allowing request", "key", key, "got", res)
		return true, 0, nil
	}
	allowed := toInt(arr[0]) == 1
	wait := time.Duration(toInt(arr[1])) * time.Millisecond
	return allowed, wait, nil
}

func toInt(v any) int {
	switch n := v.(type) {
	case int64:
		return int(n)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	default:
		return 0
	}
}

// RatePerMinute переводит «запросов в минуту» в единицы Middleware (токенов/мс).
// Нужен, чтобы ни один вызов не передал «20» и не получил 20 000 запросов в секунду.
func RatePerMinute(perMin float64) float64 { return perMin / 60_000.0 }

// Middleware пишет 429 в документированном конверте и ставит Retry-After.
// name участвует в имени ключа, чтобы разные маршруты не отъедали бюджет друг у друга.
// ВНИМАНИЕ К ЕДИНИЦАМ: rate — это токенов за МИЛЛИСЕКУНДУ, потому что bucketLua
// считает elapsed в мс. 0.01 = 10 в секунду = 600 в минуту. Наружу передают результат
// httpx.RatePerMinute (она объявлением выше), а не голое число: «20 в минуту», записанное
// как 20, дало бы 20 000 запросов в секунду и молча отключило бы лимит.
func (l *Limiter) Middleware(name string, rate float64, burst int, key func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			allowed, wait, _ := l.Allow(r.Context(), "rl:"+name+":"+key(r), math.Max(0, rate), max(burst, 1))
			if !allowed {
				if wait < time.Second {
					wait = time.Second
				}
				w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
				WriteError(w, r, http.StatusTooManyRequests, ErrRateLimited,
					"too many requests", map[string]any{"retry_after_ms": wait.Milliseconds()})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
