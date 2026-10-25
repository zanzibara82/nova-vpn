package admin

import (
	"net/http"
	"strings"
	"time"

	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/httpx"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// login — единственный анонимный маршрут пакета. Формой он повторяет вход участника
// (задача 17) намеренно: тот же конверт отказа, та же прогрессивная задержка, тот же
// LoginGuard. Разница в двух вещах — таблица admin_users вместо users и токен с iss
// «novavpn-admin» вместо пользовательского.
func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var in loginRequest
	if !h.decode(w, r, &in) {
		return
	}
	// Нормализация как при входе участника: цитируем один источник правила, чтобы
	// «админ зарегистрирован с пробелом» и «админ вводит с пробелом» не разошлись.
	email := strings.ToLower(strings.TrimSpace(in.Email))
	ip := auth.ClientIP(r)
	ipStr := ""
	if ip != nil {
		ipStr = ip.String()
	}

	row, err := h.q.AdminByEmail(r.Context(), email)
	if noRows(err) {
		h.refused(w, r, "unknown_email", email, ipStr)
		return
	}
	if err != nil {
		h.internal(w, r, err)
		return
	}
	if !auth.VerifyPassword(row.PasswordHash, in.Password) {
		h.refused(w, r, "bad_password", email, ipStr)
		return
	}
	// Оракул закрыт так же, как у участников: неизвестный email и неверный пароль
	// дают одно тело, и обе ветки проходят через одну задержку. Различие живёт только
	// в журнале.
	h.guard.Reset(r.Context(), email, ipStr)
	tok, err := h.iss.Issue(r.Context(), row.ID)
	if err != nil {
		h.internal(w, r, err)
		return
	}
	if err := httpx.WriteJSON(w, http.StatusOK, session{
		AccessToken: tok.Value,
		TokenType:   "bearer",
		// То же число, что стоит в exp токена, а не второе из конфигурации:
		// расходование «обещали 600, протух через 300» клиент заметил бы сам.
		ExpiresIn: int(h.iss.TTL().Seconds()),
	}); err != nil {
		h.log.Error("admin login write", "err", err)
	}
}

// refused — отказ входа. Причина уходит в журнал, наружу — один и тот же 401.
func (h *Handler) refused(w http.ResponseWriter, r *http.Request, reason, email, ip string) {
	h.log.Warn("admin login failed", "reason", reason,
		"request_id", httpx.RequestIDFromContext(r.Context()))
	d := h.guard.Delay(r.Context(), email, ip)
	if d > 0 {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context().Done():
			return // клиент ушёл: писать некому, горутину на несколько секунд не держим
		}
	}
	httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrInvalidCredentials,
		"email или пароль не подходят", nil)
}
