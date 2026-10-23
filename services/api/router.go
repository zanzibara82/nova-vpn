// Package api собирает http.Handler из модулей. Бизнес-логики здесь нет: auth,
// devices и entitlements отвечают за правила, этот пакет решает, что с чем
// соединить и какие лимиты навесить.
package api

import (
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/config"
	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/devices"
	"github.com/novavpn/novavpn/internal/entitlements"
	"github.com/novavpn/novavpn/internal/httpx"
)

// Окна лимитов. Спецификация §5.2 требует «register/login — по IP и по аккаунту»,
// но не задаёт чисел: числа — решение A-1, и правка умещается в одну строку.
// Осью «по аккаунту» для login заведует LoginGuard (прогрессивная задержка),
// поэтому здесь остаётся IP.
const (
	// anyPerMin — базовое окно на IP для любого запроса, включая те, что не
	// совпали ни с одним маршрутом: 404/405 обслуживает Envelope вне decorators,
	// и без этого окна «несуществующий путь» оставался бы единственным
	// endpoint'ом без лимита.
	anyPerMin = 300.0
	anyBurst  = 60
	// Анонимные маршруты: bucket на пару (маршрут, IP) — register, login,
	// refresh и logout не съедают бюджет друг у друга.
	anonPerMin = 20.0
	anonBurst  = 5
	// Закрытые маршруты: bucket на пользователя.
	userPerMin = 600.0
	userBurst  = 50
)

// planSlug — единственный план A-1; он же seed из миграции 0003 (задача 4).
const planSlug = "internal-default"

type Deps struct {
	Cfg  config.Config
	Pool *pgxpool.Pool
	RDB  *redis.Client
	Ent  *entitlements.Service
	Log  *slog.Logger
}

func NewRouter(d Deps) http.Handler {
	q := db.New(d.Pool)
	lim := httpx.NewLimiter(d.RDB, d.Log)
	deny := auth.NewRedisDenylist(d.RDB, d.Log)
	iss := auth.NewIssuer(d.Cfg.JWTSecret, d.Cfg.AccessTTL)
	sess := auth.NewSessionService(q, iss, deny, d.Cfg.RefreshTTL, d.Log)
	guard := auth.NewLoginGuard(d.RDB, d.Log)

	// "/" здесь нет намеренно: с catch-all'ом Envelope теряет отличие 404 от 405.
	mux := http.NewServeMux()

	dec := httpx.Decorators{
		// Закрытый маршрут: сначала проверка access JWT и denylist, потом bucket
		// на пользователя. Порядок важен — userKey читает user id из контекста,
		// а появляется он только после auth.Middleware.
		Auth: func(next http.Handler) http.Handler {
			return auth.Middleware(sess, deny)(
				lim.Middleware("user", httpx.RatePerMinute(userPerMin), userBurst, userKey)(next))
		},
		Anonymous: lim.Middleware("anon", httpx.RatePerMinute(anonPerMin), anonBurst, routeIPKey(mux)),
	}

	mux.HandleFunc("GET /debug/health", health)

	// Модуль объявляет маршруты и то, закрыт ли каждый; политика (JWT, лимиты,
	// числа) — здесь. Поэтому register и login не монтируются второй раз:
	// повторный mux.Handle на тот же шаблон — паника, а не ошибка компиляции.
	auth.NewHandler(sess, d.Pool, d.Ent, guard, planSlug, d.Log).RegisterRoutes(mux, dec)
	devices.NewHandler(devices.NewService(d.Pool, d.Ent),
		httpx.NewIdempotency(httpx.NewPGIdempotency(d.Pool))).RegisterRoutes(mux, dec)

	// Порядок цепочки: request id (чтобы конверт 404 имел что поставить в
	// request_id), журнал (видит и 429, и панику, и называет маршрут до диспетчера),
	// базовое окно по IP, конверт.
	baseline := lim.Middleware("any", httpx.RatePerMinute(anyPerMin), anyBurst, ipKey)
	return httpx.NewRequestID(httpx.Logging(baseline(httpx.Envelope(mux)), mux, d.Log))
}

// health — статический ответ: жив ли процесс. Проверок БД и Redis здесь нет
// сознательно: readiness с зависимостями и метрики появляются в цикле C, а
// «health» с таймаутом на базу сам становится источником отказов.
func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

// routeIPKey — bucket на пару (маршрут, IP). Имя маршрута спрашивается у самого
// ServeMux: Handler(r) — единственная публичная возможность это сделать, и она
// безопасна для параллельных запросов, потому что регистрация всех маршрутов
// закончена до старта сервера.
func routeIPKey(mux *http.ServeMux) func(*http.Request) string {
	return func(r *http.Request) string {
		_, pattern := mux.Handler(r)
		return pattern + "|" + ipKey(r)
	}
}

func ipKey(r *http.Request) string {
	// Единственный источник IP — auth.ClientIP (задача 17): он берёт RemoteAddr и
	// намеренно не верит X-Forwarded-For, потому что доверять заголовку без
	// настроенного списка прокси — это способ обойти собственный лимит. Решению
	// «сервер стоит за reverse proxy, где RemoteAddr у всех один» посвящён
	// отдельный пункт в цикле A-3 (Ansible + балансировщик), здесь оно было бы
	// догадкой.
	if ip := auth.ClientIP(r); ip != nil {
		return ip.String()
	}
	return "unknown"
}

func userKey(r *http.Request) string {
	id, ok := httpx.UserIDFromContext(r.Context())
	if !ok {
		return "anonymous"
	}
	return id.String()
}
