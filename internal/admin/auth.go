package admin

import (
	"log/slog"
	"net/http"

	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/httpx"
)

// deniedMessage — единственный текст отказа. «Токена нет», «токен не разобран» и
// «токен пользовательский» наружу неразличимы: разница была бы оракулом «какой класс
// токенов сюда присылают», а §2 требует, чтобы отказ не помогал перебору.
const deniedMessage = "требуется токен администратора"

// Middleware проверяет админский JWT и кладёт субъекта в контекст.
//
// Разделение ролей держится на iss: у пользовательского и админского токена один
// секрет, а subject у обоих — uuid, так что различить «это id участника» и «это id
// администратора» по форме невозможно. Проверяющий их Issuer обязан сверять издателя,
// иначе токен участника открывал бы /api/v1/admin/*.
//
// Права конкретного админа здесь не проверяются: в A-2 все администраторы равны, и
// это решение, а не недосмотр (§5.1 не знает ролей внутри роли; разделение прав
// отнесено в цикл C).
func Middleware(iss *auth.Issuer, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := auth.Bearer(r)
			if raw == "" {
				deny(w, r, log, "missing")
				return
			}
			claims, err := iss.Parse(raw)
			if err != nil {
				// Причина «почему не приняли» уходит в журнал, а не в ответ.
				deny(w, r, log, "token_rejected")
				return
			}
			next.ServeHTTP(w, r.WithContext(httpx.WithAdminID(r.Context(), claims.UserID)))
		})
	}
}

func deny(w http.ResponseWriter, r *http.Request, log *slog.Logger, reason string) {
	log.Warn("admin token refused", "reason", reason,
		"request_id", httpx.RequestIDFromContext(r.Context()))
	httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrUnauthenticated, deniedMessage, nil)
}
