package connections

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/httpx"
)

type Handler struct {
	svc   *Service
	idem  *httpx.Idempotency
	limit func(http.Handler) http.Handler
}

// NewHandler собирает HTTP-слой профилей. Ограничитель выдачи передаётся функцией, а
// не конструктором лимитера: политику (число, окно, ключ) решает сборщик приложения,
// модуль знает только, в каком порядке навесить обёртки.
func NewHandler(svc *Service, idem *httpx.Idempotency, issueLimiter func(http.Handler) http.Handler) *Handler {
	return &Handler{svc: svc, idem: idem, limit: issueLimiter}
}

type profileView struct {
	ID           string     `json:"id"`
	DeviceID     string     `json:"device_id"`
	ServerID     string     `json:"server_id"`
	AddressV4    string     `json:"address_v4"`
	Status       string     `json:"status"`
	IssuedAt     time.Time  `json:"issued_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	OverlapUntil *time.Time `json:"overlap_valid_until"`
	RevokedAt    *time.Time `json:"revoked_at"`
}

func toView(p db.VpnProfile) profileView {
	return profileView{
		ID: p.ID.String(), DeviceID: p.DeviceID.String(), ServerID: p.ServerID.String(),
		AddressV4: p.AddressV4.String(), Status: string(p.Status),
		IssuedAt: p.IssuedAt, ExpiresAt: p.ExpiresAt,
		OverlapUntil: p.OverlapValidUntil, RevokedAt: p.RevokedAt,
	}
}

// RegisterRoutes монтирует пять маршрутов §5.1. Все закрыты: профиль, адрес в
// туннеле и текст конфига — это доступ человека, а не справочная информация.
//
// Порядок обёрток на выдаче важен и зафиксирован здесь, а не в сборщике:
// проверка заголовка идемпотентности идёт раньше идемпотентности (иначе тест с
// nil-хранилищем проходил бы молча), а ограничитель — раньше записи слота, чтобы
// отклонённый по лимиту запрос не оставлял занятой ключ.
func (h *Handler) RegisterRoutes(mux *http.ServeMux, dec httpx.Decorators) {
	var issue http.Handler = http.HandlerFunc(h.issueInner)
	if h.idem != nil {
		issue = h.idem.Middleware("profile_issue")(issue)
	}
	if h.limit != nil {
		issue = h.limit(issue)
	}
	issue = requireKey(issue)

	mux.Handle("POST /api/v1/devices/{id}/profiles", dec.Auth(issue))
	mux.Handle("GET /api/v1/devices/{id}/profiles", dec.Auth(http.HandlerFunc(h.list)))
	mux.Handle("GET /api/v1/devices/{id}/profiles/{serverID}", dec.Auth(http.HandlerFunc(h.get)))
	mux.Handle("DELETE /api/v1/devices/{id}/profiles/{serverID}", dec.Auth(http.HandlerFunc(h.revoke)))
	mux.Handle("GET /api/v1/devices/{id}/profiles/{serverID}/config", dec.Auth(http.HandlerFunc(h.config)))
}

// requireKey — обёртка «заголовок обязателен». Вынесена из хендлера, потому что
// проверка обязана стоять до любой обёртки идемпотентности, а не внутри неё.
func requireKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Idempotency-Key") == "" {
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrIdempotencyKeyRequired,
				"заголовок Idempotency-Key обязателен при выдаче профиля", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// pathDevice и pathServer — два шага одной проверки: проверяется и то, и другое
// отдельно, а в details называется поле, чтобы клиент понимал, что именно починить.
func (h *Handler) pathDevice(w http.ResponseWriter, r *http.Request) (uuid.UUID, uuid.UUID, bool) {
	userID, ok := httpx.UserIDFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrUnauthenticated,
			"требуется аутентификация", nil)
		return uuid.Nil, uuid.Nil, false
	}
	deviceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"идентификатор устройства должен быть uuid", map[string]any{"field": "id"})
		return uuid.Nil, uuid.Nil, false
	}
	return userID, deviceID, true
}

func (h *Handler) pathServer(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	serverID, err := uuid.Parse(r.PathValue("serverID"))
	if err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"идентификатор сервера должен быть uuid", map[string]any{"field": "serverID"})
		return uuid.Nil, false
	}
	return serverID, true
}

// notFound — единственный ответ для «чужое» и «нет такого». Различие в теле
// превратило бы эти маршруты в оракул: по нему перебирали бы, чужим является
// устройство, не угадывая владельца.
func notFound(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrNotFound, "объект не найден", nil)
}

func (h *Handler) issueInner(w http.ResponseWriter, r *http.Request) {
	userID, deviceID, ok := h.pathDevice(w, r)
	if !ok {
		return
	}
	var in struct {
		ServerID string `json:"server_id"`
	}
	if err := httpx.DecodeJSON(r, &in, 1<<14); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"некорректное тело запроса", nil)
		return
	}
	serverID, err := uuid.Parse(in.ServerID)
	if err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrInvalidRequest,
			"server_id должен быть uuid", map[string]any{"field": "server_id"})
		return
	}
	p, err := h.svc.Issue(r.Context(), userID, deviceID, serverID)
	switch {
	case err == nil:
		_ = httpx.WriteJSON(w, http.StatusCreated, toView(p))
	case errors.Is(err, ErrForbiddenDevice), errors.Is(err, ErrServerUnknown):
		notFound(w, r)
	case errors.Is(err, ErrDeviceRevoked):
		httpx.WriteError(w, r, http.StatusForbidden, httpx.ErrForbidden,
			"устройство отозвано", nil)
	case errors.Is(err, ErrNoSubscription):
		httpx.WriteError(w, r, http.StatusForbidden, httpx.ErrForbidden,
			"нет активной подписки", nil)
	case errors.Is(err, ErrServerNotAvailable):
		httpx.WriteError(w, r, http.StatusConflict, httpx.ErrServerNotAvailable,
			"сервер недоступен для выдачи", nil)
	case errors.Is(err, ErrAlreadyActive):
		httpx.WriteError(w, r, http.StatusConflict, httpx.ErrConflict,
			"профиль уже выдан", nil)
	case errors.Is(err, ErrPoolExhausted):
		// Тот же код, что и у других конфликтов, но с отличием в details: «выбери
		// другой сервер» и «в этом пуле нечего дать» для клиента — разные действия.
		httpx.WriteError(w, r, http.StatusConflict, httpx.ErrConflict,
			"свободных адресов на этом сервере нет", map[string]any{"reason": "pool_exhausted"})
	case errors.Is(err, ErrAddressRace):
		httpx.WriteError(w, r, http.StatusConflict, httpx.ErrConflict,
			"выдача не состоялась из-за параллельного занятия адреса, повторите запрос",
			map[string]any{"reason": "address_race"})
	default:
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrInternal,
			"внутренняя ошибка", nil)
	}
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	userID, deviceID, ok := h.pathDevice(w, r)
	if !ok {
		return
	}
	items, err := h.svc.List(r.Context(), userID, deviceID)
	if errors.Is(err, ErrForbiddenDevice) {
		notFound(w, r)
		return
	}
	if err != nil {
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrInternal,
			"внутренняя ошибка", nil)
		return
	}
	out := make([]profileView, 0, len(items))
	for _, p := range items {
		out = append(out, toView(p))
	}
	// Пустой список — `{"profiles":[]}`: «профилей нет» это состояние, а не 404.
	_ = httpx.WriteJSON(w, http.StatusOK, map[string]any{"profiles": out})
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	userID, deviceID, ok := h.pathDevice(w, r)
	if !ok {
		return
	}
	serverID, ok := h.pathServer(w, r)
	if !ok {
		return
	}
	p, err := h.svc.Profile(r.Context(), userID, deviceID, serverID)
	switch {
	case err == nil:
		_ = httpx.WriteJSON(w, http.StatusOK, toView(p))
	case errors.Is(err, ErrForbiddenDevice), errors.Is(err, ErrNotActive):
		notFound(w, r)
	default:
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrInternal,
			"внутренняя ошибка", nil)
	}
}

// stateOf читает последний профиль пары, чтобы различить «профиля не было никогда»
// (404) и «профиль есть, но не годен» (409 с настоящим статусом). Различие требует
// таблица §5.2, а один сервисный отказ ErrNotActive его не несёт — поэтому здесь
// второй запрос, а не догадка по тексту ошибки.
func (h *Handler) stateOf(w http.ResponseWriter, r *http.Request, userID, deviceID, serverID uuid.UUID) (db.ProfileStatus, bool) {
	p, err := h.svc.Profile(r.Context(), userID, deviceID, serverID)
	switch {
	case err == nil:
		return p.Status, true
	case errors.Is(err, ErrForbiddenDevice), errors.Is(err, ErrNotActive):
		notFound(w, r)
	default:
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrInternal,
			"внутренняя ошибка", nil)
	}
	return "", false
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	userID, deviceID, ok := h.pathDevice(w, r)
	if !ok {
		return
	}
	serverID, ok := h.pathServer(w, r)
	if !ok {
		return
	}
	status, ok := h.stateOf(w, r, userID, deviceID, serverID)
	if !ok {
		return
	}
	if status != db.ProfileStatusActive {
		// Отозванный остаётся 409, а не «204 уже хорошо»: человек должен увидеть,
		// что повторный отзыв ничего не изменил, а не получить молчаливый успех.
		httpx.WriteError(w, r, http.StatusConflict, httpx.ErrConflict,
			"профиль не активен", map[string]any{"status": string(status)})
		return
	}
	if _, err := h.svc.Revoke(r.Context(), userID, deviceID, serverID); err != nil {
		switch {
		case errors.Is(err, ErrNotActive):
			// status прочитан до отзыва и к этому моменту уже неверен: строку
			// отозвали параллельно. Наружу уходит настоящее состояние из базы.
			actual, ok := h.stateOf(w, r, userID, deviceID, serverID)
			if !ok {
				return
			}
			httpx.WriteError(w, r, http.StatusConflict, httpx.ErrConflict,
				"профиль не активен", map[string]any{"status": string(actual)})
		case errors.Is(err, ErrForbiddenDevice):
			notFound(w, r)
		default:
			httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrInternal,
				"внутренняя ошибка", nil)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) config(w http.ResponseWriter, r *http.Request) {
	userID, deviceID, ok := h.pathDevice(w, r)
	if !ok {
		return
	}
	serverID, ok := h.pathServer(w, r)
	if !ok {
		return
	}
	text, err := h.svc.ConfigText(r.Context(), userID, deviceID, serverID)
	if err != nil {
		if errors.Is(err, ErrForbiddenDevice) || errors.Is(err, ErrServerUnknown) {
			notFound(w, r)
			return
		}
		if errors.Is(err, ErrNotActive) {
			// Статус в details — настоящий, из базы: «почему не отдаём» без
			// перечитывания профиля было бы догадкой.
			status, ok := h.stateOf(w, r, userID, deviceID, serverID)
			if !ok {
				return
			}
			httpx.WriteError(w, r, http.StatusConflict, httpx.ErrConflict,
				"профиль не активен", map[string]any{"status": string(status)})
			return
		}
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrInternal,
			"внутренняя ошибка", nil)
		return
	}
	// text/plain, а не JSON: клиент сохраняет ответ как файл и отдаёт его
	// утилитам wireguard. Оборачивание в JSON вынудило бы разворачивать строку с
	// экранированными переводами строк — то есть терять ровно то, ради чего конфиг
	// и передаётся целиком. Кэшировать его нельзя: конфиг — доступ, который
	// отзывают, и ответ из кэша после отзыва означал бы рабочий доступ.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(text))
}
