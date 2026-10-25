package admin

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/audit"
	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/db"
)

type lockRequest struct {
	Reason string `json:"reason"`
}

type createAdminRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// getUser — просмотр аккаунта. Запрос AdminUserView выбирает заведомо меньше, чем
// UserByID: тот берёт password_hash, и «мы его просто не показали» не доказывает, что
// хэш не ушёл клиенту. Здесь его нет ни в выборке, ни в типе ответа.
func (h *Handler) getUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.subject(w, r); !ok {
		return
	}
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	row, err := h.q.AdminUserView(r.Context(), id)
	if noRows(err) {
		h.refuse(w, r, ErrUserUnknown)
		return
	}
	if err != nil {
		h.internal(w, r, err)
		return
	}
	devices, err := h.q.LiveDevicesByUser(r.Context(), id)
	if err != nil {
		h.internal(w, r, err)
		return
	}
	// Окно объёмов — TrafficWindowDays назад от сегодняшней даты: «весь срок» это
	// device_day_traffic без границы, и он растёт быстрее, чем экран админа.
	traffic, err := h.q.TrafficByUserSince(r.Context(), db.TrafficByUserSinceParams{
		UserID: id, Day: trafficWindowStart(),
	})
	if err != nil {
		h.internal(w, r, err)
		return
	}
	h.write(w, r, http.StatusOK, userRow{
		ID: row.ID, Email: row.Email, DisplayName: row.DisplayName,
		Status: string(row.Status), LockedReason: row.LockedReason,
		Locale: row.Locale, CreatedAt: row.CreatedAt,
		Devices: deviceView(devices), Traffic: trafficView(traffic),
	})
}

// lockUser снимает доступ целиком: учётную запись, все живые профили, занятые адреса
// и refresh-семьи. Порядок внутри транзакции — не косметика: advisory-замок сервера
// держит и аллокация адреса (задача 4), поэтому выдача новому профилю не может
// «проскочить» между чтением списка серверов и отзывом.
func (h *Handler) lockUser(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.subject(w, r)
	if !ok {
		return
	}
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in lockRequest
	if !h.decode(w, r, &in) {
		return
	}
	// Причина проверяется до транзакции, а не «внутри, и тогда откат»: отказ по полю
	// reason не имеет права оставить ни изменения, ни следа в аудите.
	reason, ok := h.requiredReason(w, r, in.Reason)
	if !ok {
		return
	}
	var result lockResult
	err := audit.Do(r.Context(), h.pool, audit.Action{
		AdminID: adminID, Action: db.AuditActionUserLocked,
		TargetType: "user", TargetID: id.String(),
		Reason: reason, RequestID: requestIDForAction(r),
	}, func(tx *db.Queries) error {
		user, err := tx.UserByID(r.Context(), id)
		if noRows(err) {
			return ErrUserUnknown
		}
		if err != nil {
			return err
		}
		// Уже заблокированного блокировать нельзя: второй вызов молча перезаписал бы
		// причину, и она исчезла бы из единственного места, где её видно.
		if user.Status == db.UserStatusLocked {
			return ErrAlreadyLocked
		}
		servers, err := tx.ServersOfUserProfiles(r.Context(), id)
		if err != nil {
			return err
		}
		for _, serverID := range servers {
			if err := tx.LockServerRow(r.Context(), serverID.String()); err != nil {
				return err
			}
		}
		if err := tx.LockUser(r.Context(), db.LockUserParams{
			ID: id, LockedReason: &reason,
		}); err != nil {
			return err
		}
		// Продлиться нельзя: refresh отзывается целиком. Текущий access доживает
		// AccessTTL — замеренное ограничение A-1, оно в §13 и здесь не прячется.
		if err := tx.RevokeAllFamiliesForUser(r.Context(), id); err != nil {
			return err
		}
		profiles, err := tx.RevokeAllProfilesOfUser(r.Context(), id)
		if err != nil {
			return err
		}
		detail, err := json.Marshal(revokeDetail{Reason: "user_locked"})
		if err != nil {
			return err
		}
		bumped := make(map[uuid.UUID]bool, len(servers))
		for _, p := range profiles {
			profileID := p.ID
			if err := tx.ReleaseAddressByProfile(r.Context(), &profileID); err != nil {
				return err
			}
			serverID := p.ServerID
			if err := tx.InsertConnectionEvent(r.Context(), db.InsertConnectionEventParams{
				UserID: &p.UserID, DeviceID: &p.DeviceID, ServerID: &serverID,
				Event: db.EventTypeProfileRevoked, Detail: detail,
			}); err != nil {
				return err
			}
			bumped[serverID] = true
		}
		// По одному bump'у на сервер: без него узел продолжал бы раздавать набор,
		// из которого человека уже вычеркнули.
		for serverID := range bumped {
			if _, err := tx.BumpServerConfigVersion(r.Context(), serverID); err != nil {
				return err
			}
		}
		result = lockResult{ID: id, Status: string(db.UserStatusLocked),
			ProfilesRevoked: len(profiles), ServersBumped: len(bumped)}
		return nil
	})
	if err != nil {
		h.refuse(w, r, err)
		return
	}
	h.write(w, r, http.StatusOK, result)
}

// unlockUser возвращает право войти, но не выданные конфиги: профили остаются
// отозванными. Иначе аудит «был отозван» расходился бы с реальным набором пиеров, а
// клиент получил бы доступ, который уже терял и не просил заново.
func (h *Handler) unlockUser(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.subject(w, r)
	if !ok {
		return
	}
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in lockRequest
	if !h.decode(w, r, &in) {
		return
	}
	reason, ok := h.requiredReason(w, r, in.Reason)
	if !ok {
		return
	}
	var result lockResult
	err := audit.Do(r.Context(), h.pool, audit.Action{
		AdminID: adminID, Action: db.AuditActionUserUnlocked,
		TargetType: "user", TargetID: id.String(),
		Reason: reason, RequestID: requestIDForAction(r),
	}, func(tx *db.Queries) error {
		user, err := tx.UserByID(r.Context(), id)
		if noRows(err) {
			return ErrUserUnknown
		}
		if err != nil {
			return err
		}
		if user.Status != db.UserStatusLocked {
			return ErrNotLocked
		}
		if err := tx.UnlockUser(r.Context(), id); err != nil {
			return err
		}
		result = lockResult{ID: id, Status: string(db.UserStatusActive)}
		return nil
	})
	if err != nil {
		h.refuse(w, r, err)
		return
	}
	h.write(w, r, http.StatusOK, result)
}

// createAdmin заводит следующего оператора. Хэширование идёт до транзакции: argon2id
// на несколько десятков миллисекунд держал бы соединение с базой занятым, а отказ по
// короткому паролю вообще не обязан её касаться.
func (h *Handler) createAdmin(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.subject(w, r)
	if !ok {
		return
	}
	var in createAdminRequest
	if !h.decode(w, r, &in) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if email == "" {
		h.badField(w, r, "email", "обязательна")
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		h.badField(w, r, "password", "должна быть не короче "+
			strconv.Itoa(auth.MinPasswordLen)+" символов")
		return
	}
	newID := uuid.New()
	var row db.InsertAdminUserRow
	err = audit.Do(r.Context(), h.pool, audit.Action{
		AdminID: adminID, Action: db.AuditActionAdminCreated,
		TargetType: "admin", TargetID: newID.String(),
		Reason:    optionalReason("", db.AuditActionAdminCreated),
		RequestID: requestIDForAction(r),
	}, func(tx *db.Queries) error {
		created, err := tx.InsertAdminUser(r.Context(), db.InsertAdminUserParams{
			ID: newID, Email: email, PasswordHash: hash,
		})
		if isUniqueViolation(err, "") {
			// email_taken занят контрактом A-1 за регистрацией участников, и второй
			// смысл тому же коду давать нельзя: клиенты различают маршруты по коду.
			return ErrEmailTakenAdmin
		}
		if err != nil {
			return err
		}
		row = created
		return nil
	})
	if err != nil {
		h.refuse(w, r, err)
		return
	}
	h.write(w, r, http.StatusCreated, adminRow{ID: row.ID, Email: row.Email,
		CreatedAt: row.CreatedAt})
}

// listAudit — журнал административных действий. Фильтра по админу и по действию нет
// намеренно: §5.1 обещает «аудит», а не «поиск по аудитам», и первая реализация
// фильтра была бы вторым источником правил, которых в контракте нет.
func (h *Handler) listAudit(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.subject(w, r); !ok {
		return
	}
	queries := r.URL.Query()
	limit, ok := h.queryInt(w, r, queries, "limit", defaultAudit, 1, maxAuditPage)
	if !ok {
		return
	}
	offset, ok := h.queryInt(w, r, queries, "offset", 0, 0, maxAuditOffset)
	if !ok {
		return
	}
	rows, err := h.q.RecentAdminAudit(r.Context(), db.RecentAdminAuditParams{
		Limit: int32(limit), Offset: int32(offset),
	})
	if err != nil {
		h.internal(w, r, err)
		return
	}
	h.write(w, r, http.StatusOK, map[string]any{"audit": auditView(rows)})
}

// queryInt — граница параметра разбивки. Потолок offset нужен не для красоты: без него
// «посмотреть историю» превращается в полное сканирование таблицы на каждом клике.
func (h *Handler) queryInt(w http.ResponseWriter, r *http.Request, q map[string][]string,
	field string, def, min, max int64) (int64, bool) {
	raw := def
	if values, ok := q[field]; ok && len(values) > 0 && values[0] != "" {
		v, err := strconv.ParseInt(values[0], 10, 32)
		if err != nil {
			h.badField(w, r, field, "должна быть целым числом")
			return 0, false
		}
		raw = v
	}
	if raw < min || raw > max {
		h.badField(w, r, field, "должна быть от "+strconv.FormatInt(min, 10)+
			" до "+strconv.FormatInt(max, 10))
		return 0, false
	}
	return raw, true
}

// trafficWindowStart — левый край окна объёмов. Дата, а не момент: device_day_traffic
// разбит по суткам, и сравнивать его с «сейчас минус 30*24 часа» значило бы терять
// часть суток на каждом запросе.
func trafficWindowStart() time.Time {
	now := nowUTC()
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).
		AddDate(0, 0, -TrafficWindowDays)
}

// revokeDetail — detail события отзыва. Причина пишется кодом, а не свободным текстом:
// выборка «кого и почему снимали» обязана читаться машиной, а человеческая причина
// действия админа живёт в аудите.
type revokeDetail struct {
	Reason string `json:"reason"`
}
