package servers

import (
	"net/http"

	"github.com/novavpn/novavpn/internal/httpx"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// RegisterRoutes монтирует каталог. Маршрут закрыт (dec.Auth) по §5.1: список
// серверов — не публичная справочная, а часть договора с подписчиком.
func (h *Handler) RegisterRoutes(mux *http.ServeMux, dec httpx.Decorators) {
	mux.Handle("GET /api/v1/servers", dec.Auth(http.HandlerFunc(h.list)))
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	if _, ok := httpx.UserIDFromContext(r.Context()); !ok {
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrUnauthenticated,
			"требуется аутентификация", nil)
		return
	}
	items, err := h.svc.Catalog(r.Context())
	if err != nil {
		// Ответ клиенту — общий текст и стабильный код: хосты, порты и координаты
		// из ошибки БД наружу не уходят (§11).
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrInternal,
			"внутренняя ошибка", nil)
		return
	}
	// Пустой каталог — `{"servers":[]}`, а не 404: «серверов нет» это состояние
	// системы, а не отсутствие запрашиваемого объекта.
	_ = httpx.WriteJSON(w, http.StatusOK, map[string]any{"servers": items})
}
