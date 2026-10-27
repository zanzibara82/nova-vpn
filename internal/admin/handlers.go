// Package admin — операционный API (спецификация §5.1, §7.6, §9): отдельная роль,
// заведение и правка серверов, выдача bootstrap-токенов, блокировка пользователей и
// журнал административных действий.
//
// Общая черта всех маршрутов пакета: каждое изменение сопровождается записью с
// причиной, и записывается она в той же транзакции, что и само изменение
// (internal/audit). «Изменили, но не записали ради чего» здесь не состояние системы.
package admin

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/novavpn/novavpn/internal/audit"
	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/httpx"
)

const (
	// maxAdminBody — 16 KiB: самая большая из админских заявок (сервер с локацией)
	// держится в сотнях байт, и тело не должно становиться способом купить процессу
	// память.
	maxAdminBody = 1 << 14

	// Окно жизни bootstrap-токена (§7.6). Нижняя граница не даёт выдать токен,
	// который узел не успеет потратить на медленной раскатке; верхняя — токен,
	// живущий дольше плановой смены паролей.
	minTTLsec     = 60
	maxTTLsec     = 86400
	defaultTTLsec = 3600

	// Границы страницы аудита: limit 500 уже не помещается на экран, а offset без
	// потолка превращает «посмотреть историю» в полное сканирование таблицы.
	maxAuditPage   = 500
	defaultAudit   = 50
	maxAuditOffset = 10000

	// TrafficWindowDays — окно трафика в GET /users/{id}. «Весь срок» — это
	// device_day_traffic без границы, и он растёт быстрее, чем экран админа.
	TrafficWindowDays = 30
)

// Ошибки правил. Хендлер различает их по errors.Is, а не по тексту: текст уходит
// клиенту, и на нём держится русскоязычный интерфейс, тогда как правило должно
// переживать правку формулировки.
var (
	ErrAdminNotFound = errors.New("admin: administrator not found")
	ErrServerUnknown = errors.New("admin: server not found")
	ErrUserUnknown   = errors.New("admin: user not found")
	ErrAlreadyLocked = errors.New("admin: account is already locked")
	ErrNotLocked     = errors.New("admin: account is not locked")
	// ErrPeersActive несёт число: §7.6 обещает админу «сколько пиеров сорвётся», и
	// это число — причина отказа, а не украшение ответа.
	ErrPeersActive  = errors.New("admin: server has active profiles")
	ErrTokenNotLive = errors.New("admin: bootstrap token is used, revoked or missing")
	// ErrEmailTakenAdmin — не httpx.ErrEmailTaken: тот код контрактом A-1 закреплён за
	// регистрацией участников, и второй смысл тому же коду давать нельзя.
	ErrEmailTakenAdmin = errors.New("admin: email is already taken")
	ErrServerTaken     = errors.New("admin: server name or public key is already used")
	ErrRetiredToOnline = errors.New("admin: retired server cannot go back to online")
	ErrServerRetired   = errors.New("admin: server is retired")
	ErrLocationGone    = errors.New("admin: location row disappeared")
)

type Handler struct {
	pool  *pgxpool.Pool
	q     *db.Queries
	iss   *auth.Issuer
	guard *auth.LoginGuard
	log   *slog.Logger
}

// NewHandler собирает модуль. Пул нужен потому, что изменение и запись аудита
// исполняются одной транзакцией (audit.Do работает пулом), а q — потому, что чтение
// идёт без транзакции и не обязано покупать соединение на каждый список.
func NewHandler(pool *pgxpool.Pool, q *db.Queries, iss *auth.Issuer,
	guard *auth.LoginGuard, log *slog.Logger) *Handler {
	return &Handler{pool: pool, q: q, iss: iss, guard: guard, log: log}
}

// RegisterRoutes монтирует маршруты. Вход — единственный анонимный: он и выдаёт
// токен, которым проверяются остальные. Остальные — под четвёртой обёрткой сборки и
// своим бакетом лимитера.
func (h *Handler) RegisterRoutes(mux *http.ServeMux, dec httpx.Decorators) {
	mux.Handle("POST /api/v1/admin/login", dec.Anonymous(http.HandlerFunc(h.login)))

	mux.Handle("GET /api/v1/admin/servers", dec.Admin(http.HandlerFunc(h.listServers)))
	mux.Handle("POST /api/v1/admin/servers", dec.Admin(http.HandlerFunc(h.createServer)))
	mux.Handle("GET /api/v1/admin/servers/{id}", dec.Admin(http.HandlerFunc(h.getServer)))
	mux.Handle("PATCH /api/v1/admin/servers/{id}", dec.Admin(http.HandlerFunc(h.patchServer)))
	mux.Handle("POST /api/v1/admin/servers/{id}/maintenance", dec.Admin(http.HandlerFunc(h.setMaintenance)))
	mux.Handle("DELETE /api/v1/admin/servers/{id}", dec.Admin(http.HandlerFunc(h.deleteServer)))

	mux.Handle("POST /api/v1/admin/servers/{id}/bootstrap-tokens", dec.Admin(http.HandlerFunc(h.issueBootstrapToken)))
	mux.Handle("GET /api/v1/admin/servers/{id}/bootstrap-tokens", dec.Admin(http.HandlerFunc(h.listBootstrapTokens)))
	mux.Handle("DELETE /api/v1/admin/bootstrap-tokens/{id}", dec.Admin(http.HandlerFunc(h.revokeBootstrapToken)))
	mux.Handle("POST /api/v1/admin/servers/{id}/node-token/revoke", dec.Admin(http.HandlerFunc(h.revokeNodeToken)))

	mux.Handle("GET /api/v1/admin/users/{id}", dec.Admin(http.HandlerFunc(h.getUser)))
	mux.Handle("POST /api/v1/admin/users/{id}/lock", dec.Admin(http.HandlerFunc(h.lockUser)))
	mux.Handle("POST /api/v1/admin/users/{id}/unlock", dec.Admin(http.HandlerFunc(h.unlockUser)))

	mux.Handle("POST /api/v1/admin/admins", dec.Admin(http.HandlerFunc(h.createAdmin)))
	mux.Handle("GET /api/v1/admin/audit", dec.Admin(http.HandlerFunc(h.listAudit)))
}

// pathUUID читает uuid из шаблона маршрута. Битый id — это отказ по полю id, а не
// 500 от uuid.Parse внутри запроса к базе: админ видит, что опечатался в адресе.
func (h *Handler) pathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		h.badField(w, r, name, "должно быть идентификатором в форме uuid")
		return uuid.Nil, false
	}
	return id, true
}

// subject читает администратора из контекста. Отсутствие значения означает, что
// маршрут смонтирован без dec.Admin: это опечатка в сборке, но ответ тот же 401, что и
// при чужом токене, потому что «не пускать» — безопасная сторона, а 500 выдал бы
// наружу устройство сборки.
func (h *Handler) subject(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, ok := httpx.AdminIDFromContext(r.Context())
	if !ok || id == uuid.Nil {
		deny(w, r, h.log, "no_subject")
		return uuid.Nil, false
	}
	return id, true
}

func (h *Handler) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := httpx.DecodeJSON(r, dst, maxAdminBody); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"тело должно быть одним JSON-объектом с полями из документации", nil)
		return false
	}
	return true
}

// decodeOptional — DELETE, у которого тела может не быть вовсе. Жёсткий decode
// превратил бы «удалить сервер» в 400 ещё до того, как хендлер увидит, что там
// живут активные профили, а §7.6 обещает админу число пиеров именно до подтверждения
// удаления. Наличие причины всё равно проверяется до изменения (requiredReason).
func (h *Handler) decodeOptional(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.ContentLength == 0 {
		return true
	}
	return h.decode(w, r, dst)
}

// badField — отказ с именем поля. Форма в консоли админа разбирает details.field, и
// «400 и угадай поле» означало бы перебирать заявку вслепую.
func (h *Handler) badField(w http.ResponseWriter, r *http.Request, field, what string) {
	httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
		"поле "+field+" "+what, map[string]any{"field": field})
}

func (h *Handler) internal(w http.ResponseWriter, r *http.Request, err error) {
	h.log.Error("admin: internal error", "err", err,
		"request_id", httpx.RequestIDFromContext(r.Context()))
	httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrInternal, "внутренняя ошибка", nil)
}

// refuse переводит ошибку правила в ответ. Один switch на весь пакет нужен, чтобы
// «409» не превращался в «500» при каждой новой ошибке, и чтобы текст оставался
// русскоязычным прикладным ответом, а не строкой драйвера.
func (h *Handler) refuse(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrAdminNotFound), errors.Is(err, ErrServerUnknown), errors.Is(err, ErrUserUnknown):
		httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrNotFound, "объект не найден", nil)
	case errors.Is(err, ErrServerTaken):
		httpx.WriteError(w, r, http.StatusConflict, httpx.ErrConflict,
			"сервер с таким именем или публичным ключом уже есть", nil)
	case errors.Is(err, ErrAlreadyLocked):
		httpx.WriteError(w, r, http.StatusConflict, httpx.ErrConflict,
			"учётная запись уже заблокирована", nil)
	case errors.Is(err, ErrNotLocked):
		httpx.WriteError(w, r, http.StatusConflict, httpx.ErrConflict,
			"учётная запись не заблокирована", nil)
	case errors.Is(err, ErrRetiredToOnline):
		httpx.WriteError(w, r, http.StatusConflict, httpx.ErrConflict,
			"выведенный из эксплуатации сервер нельзя вернуть в online", nil)
	case errors.Is(err, ErrServerRetired):
		httpx.WriteError(w, r, http.StatusConflict, httpx.ErrConflict,
			"сервер выведен из эксплуатации", nil)
	case errors.Is(err, ErrTokenNotLive):
		httpx.WriteError(w, r, http.StatusConflict, httpx.ErrConflict,
			"токен уже использован, отозван или не найден", nil)
	case errors.Is(err, ErrEmailTakenAdmin):
		httpx.WriteError(w, r, http.StatusConflict, httpx.ErrConflict,
			"администратор с таким email уже есть", nil)
	case errors.Is(err, audit.ErrReasonRequired):
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"причина действия должна быть от 3 до 500 символов", map[string]any{"field": "reason"})
	default:
		h.internal(w, r, err)
	}
}

// isUniqueViolation смотрит на код PostgreSQL, а не на текст: сообщения локализуемы и
// меняются между версиями, а код 23505 — часть контракта драйвера. Имя ограничения
// нужно, чтобы отличить нужный уникальный индекс от любого другого: у vpn_servers их
// два (name и public_key), и обоим соответствует один и тот же ответ.
func isUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return false
	}
	return constraint == "" || strings.HasSuffix(pgErr.Message, constraint)
}

// noRows — «строки нет» в терминах pgx; отдельная функция нужна, чтобы каждый хендлер
// не повторял errors.Is(err, pgx.ErrNoRows) и не путал его с настоящей ошибкой базы.
func noRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// defaultReason — причина для действия, у которого админ её не спросил. Поле
// admin_audit_logs.reason NOT NULL с CHECK 3..500, а audit.check отказывает пустой
// строке, поэтому хендлер обязан поставить что-то сам. Для «создать сервер» это и
// есть вся причина: действие не имеет альтернативной мотивации, которую мог бы знать
// только оператор. Там, где выбор реальный (удаление, блокировка, отзыв), поле reason
// обязательно и проверяется до изменения.
func defaultReason(action db.AuditAction) string {
	return "действие «" + string(action) + "» из админской консоли"
}

// optionalReason — поле reason там, где выбора нет: «создать сервер» не имеет
// альтернативной мотивации, которую знал бы только оператор. Поле admin_audit_logs.reason
// NOT NULL с CHECK 3..500, и audit.check отказывает пустой строке, поэтому хендлер
// обязан поставить что-то сам.
func optionalReason(reason string, action db.AuditAction) string {
	if r := strings.TrimSpace(reason); validReason(r) {
		return r
	}
	return defaultReason(action)
}

// requiredReason — поле reason там, где решение реальное (удаление, блокировка,
// отзыв). Пустое или неподходящее по длине возвращается ошибкой, а не дефолтом:
// подставить «действие из админской консоли» вместо причины оператор просил не нас.
// Проверка дублирует audit.check, а не откладывается на него: отказ обязан прийти до
// любого изменения, а не «внутри транзакции, и тогда откат».
func (h *Handler) requiredReason(w http.ResponseWriter, r *http.Request, reason string) (string, bool) {
	trimmed := strings.TrimSpace(reason)
	if !validReason(trimmed) {
		h.badField(w, r, "reason", "должна быть от 3 до 500 символов")
		return "", false
	}
	return trimmed, true
}

// validReason — окно 3..500 из CHECK admin_audit_reason (миграция 0003), в символах, а
// не байтами: три кириллических символа — шесть байт, и отказывать им нельзя.
func validReason(s string) bool {
	n := utf8.RuneCountInString(s)
	return n >= 3 && n <= 500
}

// requestIDForAction читает request id из контекста: он же уходит в X-Request-Id
// ответа (задача 18), и по нему запись аудита связывается со строкой журнала.
func requestIDForAction(r *http.Request) string { return httpx.RequestIDFromContext(r.Context()) }

// nowUTC — единая точка получения времени: ответ узлу и метка профиля обязаны
// сравниваться по UTC, а локальный часовой пояс контейнера сюда попадать не должен.
func nowUTC() time.Time { return time.Now().UTC() }
