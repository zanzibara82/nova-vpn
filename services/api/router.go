// Package api собирает http.Handler из модулей. Бизнес-логики здесь нет: auth,
// devices и entitlements отвечают за правила, этот пакет решает, что с чем
// соединить и какие лимиты навесить.
package api

import (
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/novavpn/novavpn/internal/admin"
	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/config"
	"github.com/novavpn/novavpn/internal/connections"
	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/devices"
	"github.com/novavpn/novavpn/internal/entitlements"
	"github.com/novavpn/novavpn/internal/httpx"
	"github.com/novavpn/novavpn/internal/nodeapi"
	"github.com/novavpn/novavpn/internal/servers"
	"github.com/novavpn/novavpn/internal/telemetry"
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
	// Выдача профиля — отдельный бакет, а не часть общего бюджета закрытых
	// маршрутов: при общем лимите один пользователь мог бы удерживать 30 выдач в
	// минуту и одновременно делать 600 списаний, то есть платить за право
	// заблокировать сервер чужим трафиком из своего же бюджета. Число и окно — §5.2,
	// окно на пользователя (ключ тот же userKey, что у dec.Auth).
	profileIssuePerMin = 30.0
	profileIssueBurst  = 5
	// Узловые маршруты: bucket на сервер (§4.1). 120 в минуту — это polling desired
	// раз в секунду с запасом на отчёты, а burst 10 держит «узёл стартовал и навалил
	// десять вызовов сразу». Числа — решение цикла A-2: спецификация просит
	// «отдельный лимит для узла», не называя их.
	nodePerMin = 120.0
	nodeBurst  = 10
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
	// Второй Issuer на том же секрете: различить id участника и id администратора
	// по форме нельзя (оба uuid), поэтому роль держится в claim'е iss, а не в догадке
	// вызывающей стороны. Отдельного env-параметра для срока админ-токена нет: второе
	// число, которое никто не просил, обязано когда-нибудь разойтись с первым.
	issAdmin := auth.NewAdminIssuer(d.Cfg.JWTSecret, d.Cfg.AccessTTL)
	sess := auth.NewSessionService(q, iss, deny, d.Cfg.RefreshTTL, d.Log)
	guard := auth.NewLoginGuard(d.RDB, d.Log)

	// "/" здесь нет намеренно: с catch-all'ом Envelope теряет отличие 404 от 405.
	mux := http.NewServeMux()

	// Контракт узла строится до decorators: обёртка dec.Node берётся у самого
	// модуля, чтобы проверка токена и маршруты опирались на один экземпляр
	// Authenticator, иначе «кто этот узел» решалось бы в двух местах.
	node := nodeapi.NewHandler(q, telemetry.NewService(d.Pool, d.RDB, d.Log), d.Log)

	dec := httpx.Decorators{
		// Закрытый маршрут: сначала проверка access JWT и denylist, потом bucket
		// на пользователя. Порядок важен — userKey читает user id из контекста,
		// а появляется он только после auth.Middleware.
		Auth: func(next http.Handler) http.Handler {
			return auth.Middleware(sess, deny)(
				lim.Middleware("user", httpx.RatePerMinute(userPerMin), userBurst, userKey)(next))
		},
		Anonymous: lim.Middleware("anon", httpx.RatePerMinute(anonPerMin), anonBurst, routeIPKey(mux)),
		// Узел — тот же порядок, что у Auth: nodeKey читает server_id из контекста,
		// а появляется он только после проверки токена. Обратно (лимитер до
		// аутентификации) означало бы общий бакет «unknown» для всех чужих токенов
		// и отсутствие лимита у настоящего узла.
		Node: func(next http.Handler) http.Handler {
			return node.NodeMiddleware()(
				lim.Middleware("node", httpx.RatePerMinute(nodePerMin), nodeBurst, nodeKey)(next))
		},
		// Админ — четвёртый класс доступа, а не «пользователь с другим id»: свой
		// iss в токене, свой бакет лимитера и право на чужие данные. Порядок тот же,
		// что у Auth и Node: adminKey читает admin_id из контекста, поэтому лимитер
		// обязан идти после проверки токена. Числа окна совпадают с пользовательскими
		// не потому, что это один бюджет, а потому что консоль оператора делает
		// столько же кликов в минуту; бакеты при этом разные.
		Admin: func(next http.Handler) http.Handler {
			return admin.Middleware(issAdmin, d.Log)(
				lim.Middleware("admin", httpx.RatePerMinute(userPerMin), userBurst, adminKey)(next))
		},
	}

	mux.HandleFunc("GET /debug/health", health)

	// Модуль объявляет маршруты и то, закрыт ли каждый; политика (JWT, лимиты,
	// числа) — здесь. Поэтому register и login не монтируются второй раз:
	// повторный mux.Handle на тот же шаблон — паника, а не ошибка компиляции.
	auth.NewHandler(sess, d.Pool, d.Ent, guard, planSlug, d.Log).RegisterRoutes(mux, dec)
	devices.NewHandler(devices.NewService(d.Pool, d.Ent),
		httpx.NewIdempotency(httpx.NewPGIdempotency(d.Pool))).RegisterRoutes(mux, dec)
	servers.NewHandler(servers.NewService(q)).RegisterRoutes(mux, dec)

	// Профили: свой ограничитель поверх того же пользователя. Порядок обёрток
	// (auth → лимит выдачи → идемпотентность → хендлер) задаёт модуль, здесь
	// решается только из чего он собран: 429 обязан случиться до записи слота
	// идемпотентности, иначе отклонённый запрос оставил бы занятой ключ.
	profileIssue := lim.Middleware("profile_issue", httpx.RatePerMinute(profileIssuePerMin),
		profileIssueBurst, userKey)
	connections.NewHandler(connections.NewService(d.Pool, d.Ent),
		httpx.NewIdempotency(httpx.NewPGIdempotency(d.Pool)), profileIssue).RegisterRoutes(mux, dec)

	// Контракт узла монтируется здесь, а не выше: маршруты /internal/v1 не зависят
	// от пользовательских, но собираются из того же пула и того же Redis.
	node.RegisterRoutes(mux, dec)

	// Админский контур — последний: он делит с остальными и пул, и LoginGuard, и
	// журнал, но не делит бакеты лимитеров. Маршрут входа смонтирован под
	// dec.Anonymous, поэтому он существует до того, как кто-то получил токен.
	admin.NewHandler(d.Pool, q, issAdmin, guard, d.Log).RegisterRoutes(mux, dec)

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

// nodeKey — бакет на узел, а не на путь: один vpn-сервер, сломавший цикл desired,
// не имеет права отъедать бюджет у остальных узлов, и тем более у чужих IP.
// "unknown" — это запрос без принятого токена: у него нет субъекта, а отказ ему
// всё равно вернётся до лимитера.
func nodeKey(r *http.Request) string {
	id, ok := httpx.ServerIDFromContext(r.Context())
	if !ok {
		return "unknown"
	}
	return id.String()
}

// adminKey — бакет на администратора, а не на IP: операторы сидят в одной сети, где
// адрес один на всех, и общий по IP бакет означал бы, что один человек с открытой
// консолью исчерпывает бюджет коллег. Без admin_id ключом становится IP — это ветка
// для маршрута, смонтированного без dec.Admin (опечатка в сборке), а не для
// отклонённого токена: отказ выдаёт сам Middleware и до лимитера не доходит.
func adminKey(r *http.Request) string {
	id, ok := httpx.AdminIDFromContext(r.Context())
	if !ok {
		return ipKey(r)
	}
	return id.String()
}
