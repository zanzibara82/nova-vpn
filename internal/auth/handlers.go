package auth

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/entitlements"
	"github.com/novavpn/novavpn/internal/httpx"
)

// maxAuthBody: пара email+password физически маленькая. 16 KiB с запасом — и тело
// не превращается в способ купить серверу память.
const maxAuthBody = 1 << 14

type Handler struct {
	sess     *SessionService
	pool     *pgxpool.Pool
	ent      *entitlements.Service
	guard    *LoginGuard
	planSlug string
	log      *slog.Logger
}

func NewHandler(sess *SessionService, pool *pgxpool.Pool, ent *entitlements.Service,
	guard *LoginGuard, planSlug string, log *slog.Logger) *Handler {
	return &Handler{sess: sess, pool: pool, ent: ent, guard: guard, planSlug: planSlug, log: log}
}

// RegisterRoutes монтирует маршруты модуля в общий ServeMux. Публичные — под
// dec.Anonymous, приватные — под dec.Auth, который передаёт сборщик (задача 18):
// модуль не решает, как устроены аутентификация и лимиты, он только объявляет,
// какой из его маршрутов закрыт.
func (h *Handler) RegisterRoutes(mux *http.ServeMux, dec httpx.Decorators) {
	// Все четыре анонимны по смыслу, но не «без лимита»: лимит по IP навешивает
	// сборщик через dec.Anonymous. refresh/logout без него — это бесплатный
	// перебор семей refresh-токенов и отзыв чужих сессий на скорость.
	mux.Handle("POST /api/v1/auth/register", dec.Anonymous(http.HandlerFunc(h.register)))
	mux.Handle("POST /api/v1/auth/login", dec.Anonymous(http.HandlerFunc(h.login)))
	mux.Handle("POST /api/v1/auth/refresh", dec.Anonymous(http.HandlerFunc(h.refresh)))
	// logout НЕ под Auth (контракт, задача 16): отзыв обязан сработать и когда
	// access уже истёк. Доказательство владения сессией — refresh-токен в теле.
	mux.Handle("POST /api/v1/auth/logout", dec.Anonymous(http.HandlerFunc(h.logout)))
	mux.Handle("GET /api/v1/me", dec.Auth(http.HandlerFunc(h.me)))
}

// credentials = components/schemas/Credentials из контракта. Полей больше нет:
// httpx.DecodeJSON стоит на DisallowUnknownFields, и «лишний» display_name в
// запросе обязан быть отвергнут, а не тихо проигнорирован.
type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *Handler) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := httpx.DecodeJSON(r, dst, maxAuthBody); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"тело должно быть одним JSON-объектом с полями из документации", nil)
		return false
	}
	return true
}

// internal — единый выход в 500. Причина уходит в журнал с request id, наружу
// не уходит никогда: текст ошибки PostgreSQL описывает схему и столбцы.
func (h *Handler) internal(w http.ResponseWriter, r *http.Request, err error) {
	h.log.Error("auth: internal error",
		"err", err, "request_id", httpx.RequestIDFromContext(r.Context()))
	httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrInternal, "внутренняя ошибка", nil)
}

func (h *Handler) writeSession(w http.ResponseWriter, status int, s Session) {
	// Токены в теле — no-store: без этого промежуточный кэш может оставить
	// действующую сессию там, где её не ждали.
	w.Header().Set("Cache-Control", "no-store")
	if err := httpx.WriteJSON(w, status, sessionView{
		AccessToken: s.AccessToken, RefreshToken: s.RefreshToken, TokenType: "Bearer",
		AccessExpiresAt: s.AccessExpiresAt, RefreshExpiresAt: s.RefreshExpiresAt,
	}); err != nil {
		h.log.Error("auth: write session", "err", err)
	}
}

type sessionView struct {
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token"`
	TokenType        string    `json:"token_type"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	var in credentials
	if !h.decode(w, r, &in) {
		return
	}
	email, ok := normalizeEmail(in.Email)
	if !ok {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"email должен быть одним адресом не длиннее 254 символов",
			map[string]any{"field": "email"})
		return
	}
	hash, err := HashPassword(in.Password)
	if err != nil {
		// Пока не создан ни пользователь, ни подписка: до HashPassword доходить
		// не должно — иначе слабый пароль уже оставил бы строку в users.
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"пароль должен быть от 10 до 1024 байт", map[string]any{"field": "password"})
		return
	}
	userID := uuid.New()
	err = db.RunInTx(r.Context(), h.pool, func(q *db.Queries) error {
		if _, err := q.InsertUser(r.Context(), db.InsertUserParams{
			ID: userID, Email: email, PasswordHash: hash, DisplayName: nil, Locale: "ru",
		}); err != nil {
			return err
		}
		return entitlements.GrantDefaultPlanTx(r.Context(), q, userID, h.planSlug)
	})
	if err != nil {
		if isEmailTaken(err) {
			httpx.WriteError(w, r, http.StatusConflict, httpx.ErrEmailTaken,
				"email уже зарегистрирован", map[string]any{"field": "email"})
			return
		}
		h.internal(w, r, err)
		return
	}
	sess, err := h.sess.NewSession(r.Context(), userID, ClientIP(r))
	if err != nil {
		h.internal(w, r, err)
		return
	}
	h.writeSession(w, http.StatusCreated, sess)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var in credentials
	if !h.decode(w, r, &in) {
		return
	}
	// Нормализация та же, что при регистрации, но без отказа на «странности»:
	// форма email здесь не тема ответа.
	email := strings.ToLower(strings.TrimSpace(in.Email))
	ip := ClientIP(r)
	ipStr := ipString(ip)

	q := db.New(h.pool)
	user, err := q.UserByEmail(r.Context(), email)
	if errors.Is(err, pgx.ErrNoRows) {
		h.penalize(w, r, email, ipStr)
		return
	}
	if err != nil {
		h.internal(w, r, err)
		return
	}
	if !VerifyPassword(user.PasswordHash, in.Password) {
		h.penalize(w, r, email, ipStr)
		return
	}
	// Про блокировку сообщаем только после верного пароля: иначе ответ сам по себе
	// становится оракулом «такой аккаунт есть».
	if user.Status != db.UserStatusActive {
		h.log.Warn("login on non-active account", "user_id", user.ID, "status", string(user.Status))
		httpx.WriteError(w, r, http.StatusForbidden, httpx.ErrAccountLocked,
			"учётная запись заблокирована", nil)
		return
	}
	h.guard.Reset(r.Context(), email, ipStr)
	sess, err := h.sess.NewSession(r.Context(), user.ID, ip)
	if err != nil {
		h.internal(w, r, err)
		return
	}
	h.writeSession(w, http.StatusOK, sess)
}

// penalize — отказ по креденшелам. И неизвестный email, и неверный пароль дают
// одно и то же тело, и обе ветки проходят через одну задержку. Фиктивную
// argon2-проверку для неизвестного email не делаем сознательно: 64 MiB на каждый
// запрос к любому адресу — это подарок тому, кто умеет слать запросы.
// Оставшийся канал (тайминг) документирован в спецификации §13.10.
func (h *Handler) penalize(w http.ResponseWriter, r *http.Request, email, ip string) {
	d := h.guard.Delay(r.Context(), email, ip)
	if d > 0 {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context().Done():
			return // клиент ушёл: писать некому, горутину на 4 секунды не держим
		}
	}
	httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrInvalidCredentials,
		"неверный email или пароль", nil)
}

func (h *Handler) refresh(w http.ResponseWriter, r *http.Request) {
	var in refreshRequest
	if !h.decode(w, r, &in) {
		return
	}
	// Границы из контракта (minLength 40, maxLength 512) — здесь, а не в parseRefresh:
	// «слишком короткий» — это нарушение схемы, а не «токена нет».
	if n := len(in.RefreshToken); n < 40 || n > 512 {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"refresh_token должен быть от 40 до 512 символов", map[string]any{"field": "refresh_token"})
		return
	}
	sess, err := h.sess.Rotate(r.Context(), in.RefreshToken, ClientIP(r))
	switch {
	case err == nil:
		h.writeSession(w, http.StatusOK, sess)
	case errors.Is(err, ErrInvalidRefreshToken), errors.Is(err, ErrExpiredRefreshToken):
		// Один код и одно сообщение для «не разобран», «семьи нет», «семья отозвана»,
		// «секрет переиспользован» и «истёк». Причины — только в журнале.
		h.log.Warn("refresh rejected", "err", err,
			"request_id", httpx.RequestIDFromContext(r.Context()))
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrRefreshTokenInvalid,
			"неверный refresh-токен", nil)
	case errors.Is(err, ErrAccountLocked):
		httpx.WriteError(w, r, http.StatusForbidden, httpx.ErrAccountLocked,
			"учётная запись заблокирована", nil)
	default:
		h.internal(w, r, err)
	}
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	var in refreshRequest
	if !h.decode(w, r, &in) {
		return
	}
	// access передаём, но не требуем: если он притащен и разобран — его jti уходит
	// в denylist, и активный токен перестаёт пускать немедленно.
	if err := h.sess.Revoke(r.Context(), in.RefreshToken, Bearer(r)); err != nil {
		if errors.Is(err, ErrInvalidRefreshToken) {
			h.log.Warn("logout with undecodable refresh token",
				"request_id", httpx.RequestIDFromContext(r.Context()))
			httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrRefreshTokenInvalid,
				"неверный refresh-токен", nil)
			return
		}
		h.internal(w, r, err)
		return
	}
	// 204 и для уже отозванной, и для несуществующей семьи: отзыв идемпотентен,
	// а различие «такой семьи нет» / «мы её уже сожгли» — ещё один оракул.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

type userView struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	DisplayName *string   `json:"display_name"`
	Status      string    `json:"status"`
	Locale      string    `json:"locale"`
	CreatedAt   time.Time `json:"created_at"`
}

type planView struct {
	Slug              string `json:"slug"`
	DeviceLimit       int    `json:"device_limit"`
	TrafficQuotaBytes *int64 `json:"traffic_quota_bytes"`
}

type usageView struct {
	Live  int `json:"live"`
	Limit int `json:"limit"`
}

type meView struct {
	User    userView  `json:"user"`
	Plan    *planView `json:"plan"`
	Devices usageView `json:"devices"`
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	userID, ok := httpx.UserIDFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrUnauthenticated,
			"требуется аутентификация", nil)
		return
	}
	q := db.New(h.pool)
	user, err := q.UserByID(r.Context(), userID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Подписанный jti живой, пользователя нет: это не «нет права», а «нет
		// субъекта» — 401, и denylist тут не при чём.
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrUnauthenticated,
			"требуется аутентификация", nil)
		return
	}
	if err != nil {
		h.internal(w, r, err)
		return
	}
	live, err := q.CountLiveDevices(r.Context(), userID)
	if err != nil {
		h.internal(w, r, err)
		return
	}
	out := meView{
		User: userView{ID: user.ID.String(), Email: user.Email, DisplayName: user.DisplayName,
			Status: string(user.Status), Locale: user.Locale, CreatedAt: user.CreatedAt},
		Devices: usageView{Live: int(live)},
	}
	ent, err := h.ent.ForUser(r.Context(), userID)
	switch {
	case err == nil:
		out.Plan = &planView{Slug: ent.Slug, DeviceLimit: ent.DeviceLimit,
			TrafficQuotaBytes: ent.TrafficQuotaBytes}
		out.Devices.Limit = ent.DeviceLimit
	case errors.Is(err, entitlements.ErrNoActiveSubscription):
		// plan: null, limit: 0. /me описывает состояние аккаунта, а не выдаёт право,
		// поэтому отсутствие подписки здесь — данные, а не отказ (403 был бы
		// неправдой про «нет доступа» там, где нужно «кончилось»).
		out.Plan = nil
	default:
		h.internal(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if err := httpx.WriteJSON(w, http.StatusOK, out); err != nil {
		h.log.Error("auth: write me", "err", err)
	}
}

// normalizeEmail — каноническая форма для uniqueness-ключа и для ключа задержки.
// citext делает UNIQUE независимым от регистра, но счётчик неудач должен считаться
// по одному и тому же адресу, а не по каждому его написанию.
func normalizeEmail(s string) (string, bool) {
	v := strings.ToLower(strings.TrimSpace(s))
	if !validEmail(v) {
		return "", false
	}
	return v, true
}

// validEmail — структурная проверка, а не валидация адреса. Настоящее подтверждение
// — письмо (цикл D); здесь цель другая: не пустить мусор, не дать email быть
// бесконечным ключом и не оставить «@» внутри local-part.
func validEmail(s string) bool {
	if len(s) == 0 || len(s) > 254 || strings.Count(s, "@") != 1 {
		return false
	}
	local, domain, _ := strings.Cut(s, "@")
	if len(local) == 0 || len(local) > 64 || len(domain) < 4 || len(domain) > 253 {
		return false
	}
	if strings.IndexFunc(local, func(r rune) bool {
		return !isLocalRune(r)
	}) >= 0 {
		return false
	}
	if strings.IndexFunc(domain, func(r rune) bool {
		return !(r == '.' || r == '-' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) >= 0 {
		return false
	}
	labels := strings.Split(domain, ".")
	for i, l := range labels {
		if len(l) == 0 || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return false
		}
		// TLD из цифр не бывает доменом: «host.123» — опечатка, а не адрес.
		if i == len(labels)-1 {
			if len(l) < 2 || strings.IndexFunc(l, func(r rune) bool {
				return r < 'a' || r > 'z'
			}) >= 0 {
				return false
			}
		}
	}
	return true
}

func isLocalRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return true
	case r == '.' || r == '_' || r == '%' || r == '+' || r == '-':
		return true
	default:
		return false
	}
}

// isEmailTaken — UNIQUE-констрейнт на citext-колонке. Имя constraint берём из
// PostgreSQL (`\d users` в контейнере с миграциями), а не из предположения: на
// колонке «email citext NOT NULL UNIQUE» имя по умолчанию — users_email_key.
// Проверяется и код 23505, и имя: без второго условия любой другой UNIQUE
// (например, кривой seed планов) выглядел бы как занятый email.
func isEmailTaken(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return false
	}
	return pgErr.ConstraintName == "users_email_key"
}
