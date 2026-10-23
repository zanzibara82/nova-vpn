package auth

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/httpx"
)

// Middleware проверяет access-токен и кладёт субъекта в контекст. Проверка права на
// конкретный объект (чужое устройство, чужой профиль) — не здесь, а в сервисе
// (спецификация §5.2: «проверка права на объект, а не только факта аутентификации»).
// Журналирование запроса делает сквозной middleware из задачи 18 — поэтому у Middleware
// нет параметра log: отказ denylist пишет сам (задача 11).
func Middleware(sess *SessionService, deny Denylist) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			value := Bearer(r)
			if value == "" {
				httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrUnauthenticated, "требуется аутентификация", nil)
				return
			}
			claims, err := sess.ParseAccess(value)
			if err != nil || claims.UserID == uuid.Nil {
				httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrUnauthenticated, "требуется аутентификация", nil)
				return
			}
			blocked, err := deny.Contains(r.Context(), claims.JTI)
			if err != nil {
				// Contains уже записал отказ в журнал. Продолжаем с blocked == false:
				// это тот же fail-open, что у rate limiter (§4.3), и он означает, что
				// при недоступном Redis отозванный access доживает свой TTL. Доступ к
				// трафику забирает не токен, а снятие пиера на узле (§5.3), и оно от
				// Redis не зависит.
				blocked = false
			}
			if blocked {
				httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrUnauthenticated, "требуется аутентификация", nil)
				return
			}
			next.ServeHTTP(w, r.WithContext(httpx.WithUserID(r.Context(), claims.UserID)))
		})
	}
}

// Bearer возвращает токен из заголовка Authorization; "" — если заголовка нет, схема
// не Bearer или после схемы пусто. Регистр схемы не значим (RFC 9110), но сравнивать
// только слово «Bearer» без завершающего пробела нельзя: «BearerX abc» обязан быть отвергнут.
func Bearer(r *http.Request) string {
	const prefix = "Bearer "
	v := r.Header.Get("Authorization")
	if len(v) < len(prefix) || !strings.EqualFold(v[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(v[len(prefix):])
}

// ClientIP берёт адрес из RemoteAddr. X-Forwarded-For не читается: этот заголовок
// контролирует клиента, и доверять ему — значит отдать ему возможность подделать ключ
// rate limit (спецификация §6: ip хранится только для анти-злоупотреблений).
// Оператор, ставящий TLS-терминатор перед API, обязан передать настоящий адрес
// источником (proxy protocol или связка 1:1), а не заголовком.
func ClientIP(r *http.Request) *netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.IsUnspecified() {
		return nil
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	return &addr
}

func ipString(a *netip.Addr) string {
	if a == nil {
		return "unknown"
	}
	return a.String()
}
