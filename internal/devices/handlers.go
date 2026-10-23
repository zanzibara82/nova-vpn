package devices

import (
	"errors"
	"net/http"
	"time"

	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/entitlements"
	"github.com/novavpn/novavpn/internal/httpx"
)

type Handler struct {
	svc  *Service
	idem *httpx.Idempotency
}

func NewHandler(svc *Service, idem *httpx.Idempotency) *Handler {
	return &Handler{svc: svc, idem: idem}
}

type deviceView struct {
	ID        string     `json:"id"`
	PublicKey string     `json:"public_key"`
	Platform  string     `json:"platform"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	LastSeen  *time.Time `json:"last_seen_at"`
	RevokedAt *time.Time `json:"revoked_at"`
}

func toView(d db.Device) deviceView {
	return deviceView{ID: d.ID.String(), PublicKey: d.PublicKey, Platform: string(d.Platform),
		Name: d.Name, CreatedAt: d.CreatedAt, LastSeen: d.LastSeenAt, RevokedAt: d.RevokedAt}
}

// RegisterRoutes — единый для всех модулей способ монтирования (контракт и файл
// internal/httpx/decorators.go — в начале этой задачи): сборщик передаёт ServeMux и
// две обёртки, модуль решает только то, какой из его маршрутов закрыт. Оба маршрута
// устройств закрыты, поэтому оба под dec.Auth.
func (h *Handler) RegisterRoutes(mux *http.ServeMux, dec httpx.Decorators) {
	mux.Handle("POST /api/v1/devices", dec.Auth(http.HandlerFunc(h.register)))
	mux.Handle("GET /api/v1/devices", dec.Auth(http.HandlerFunc(h.list)))
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	// Идемпотентность включается только с реальным хранилищем; требование заголовка
	// при этом проверяется всегда — иначе тест с nil-хранилищем проходил бы молча.
	if r.Header.Get("Idempotency-Key") == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrIdempotencyKeyRequired,
			"заголовок Idempotency-Key обязателен при регистрации устройства", nil)
		return
	}
	var wrapped http.Handler = http.HandlerFunc(h.registerInner)
	if h.idem != nil {
		wrapped = h.idem.Middleware("device_create")(http.HandlerFunc(h.registerInner))
	}
	wrapped.ServeHTTP(w, r)
}

func (h *Handler) registerInner(w http.ResponseWriter, r *http.Request) {
	userID, ok := httpx.UserIDFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrUnauthenticated, "требуется аутентификация", nil)
		return
	}
	var in struct {
		PublicKey string `json:"public_key"`
		Platform  string `json:"platform"`
		Name      string `json:"name"`
	}
	if err := httpx.DecodeJSON(r, &in, 1<<14); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest, "некорректное тело запроса", nil)
		return
	}
	d, err := h.svc.Register(r.Context(), userID, RegisterInput{
		PublicKey: in.PublicKey, Platform: in.Platform, Name: in.Name,
	})
	switch {
	case err == nil:
		_ = httpx.WriteJSON(w, http.StatusCreated, toView(d))
	case errors.Is(err, ErrInvalidKey):
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"public_key должен быть каноническим base64 от 32 байт",
			map[string]any{"field": "public_key"})
	case errors.Is(err, ErrInvalidPlatform):
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"неподдерживаемая платформа", map[string]any{"field": "platform"})
	case errors.Is(err, ErrInvalidName):
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"имя должно быть от 1 до 64 символов", map[string]any{"field": "name"})
	case errors.Is(err, ErrDeviceLimit):
		lim := 0
		if e, err := h.svc.ent.ForUser(r.Context(), userID); err == nil {
			lim = e.DeviceLimit
		}
		httpx.WriteError(w, r, http.StatusConflict, httpx.ErrDeviceLimitReached,
			"лимит устройств этого плана исчерпан", map[string]any{"limit": lim})
	case errors.Is(err, ErrDuplicateKey):
		httpx.WriteError(w, r, http.StatusConflict, httpx.ErrDuplicateDevice,
			"устройство с таким публичным ключом уже существует", nil)
	case errors.Is(err, entitlements.ErrNoActiveSubscription):
		httpx.WriteError(w, r, http.StatusForbidden, httpx.ErrForbidden,
			"нет активной подписки", nil)
	default:
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrInternal, "внутренняя ошибка", nil)
	}
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	userID, ok := httpx.UserIDFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrUnauthenticated, "требуется аутентификация", nil)
		return
	}
	items, err := h.svc.List(r.Context(), userID)
	if err != nil {
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrInternal, "внутренняя ошибка", nil)
		return
	}
	out := make([]deviceView, 0, len(items))
	for _, d := range items {
		out = append(out, toView(d))
	}
	_ = httpx.WriteJSON(w, http.StatusOK, map[string]any{"devices": out})
}
