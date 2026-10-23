package httpx

import (
	"context"
	"net/http"
)

type ctxKey int

const requestIDKey ctxKey = 1

func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// NewRequestID присваивает идентификатор и пишет доступный для клиента заголовок.
// Клиентский X-Request-Id принимается только если он уже правильного формата:
// иначе заголовок становится каналом для подстановки в логи.
//
// Журнал запроса здесь больше не пишется: строка обязана быть одна, и её делает
// Logging. Здесь остаются контекст и заголовок.
func NewRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if !isHex16(id) {
			id = newRequestID()
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(withRequestID(r.Context(), id)))
	})
}

func isHex16(s string) bool {
	if len(s) != 16 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
