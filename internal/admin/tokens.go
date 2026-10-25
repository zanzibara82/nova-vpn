package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/audit"
	"github.com/novavpn/novavpn/internal/db"
)

// bootstrapSecretBytes — длина секрета при регистрации узла: те же 32 байта, что у
// узлового токена задачи 11, потому что и расход у них один (sha256 в базу, значение
// наружу один раз).
const bootstrapSecretBytes = 32

type bootstrapRequest struct {
	TTLSec *int64 `json:"ttl_sec"`
}

type reasonRequest struct {
	Reason string `json:"reason"`
}

// issueBootstrapToken выдаёт одноразовый стартовый токен. Секрет показывается ровно
// один раз, в этом ответе: в базе лежит sha256, поэтому ни список, ни журнал, ни
// повторный вызов его не вернут — и потерять его означает перевыпустить, а не
// вспомнить.
func (h *Handler) issueBootstrapToken(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.subject(w, r)
	if !ok {
		return
	}
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in bootstrapRequest
	if !h.decodeOptional(w, r, &in) {
		return
	}
	ttl, ok := h.ttlSeconds(w, r, in.TTLSec)
	if !ok {
		return
	}
	srv, err := h.q.ServerByID(r.Context(), id)
	if noRows(err) {
		h.refuse(w, r, ErrServerUnknown)
		return
	}
	if err != nil {
		h.internal(w, r, err)
		return
	}
	// Выведенному узлу токен некому потратить: стартовый токен нужен тому, кто ещё
	// не зарегистрировался, а retired регистрировать нельзя.
	if srv.MaintenanceStatus == db.MaintenanceStatusRetired {
		h.refuse(w, r, ErrServerRetired)
		return
	}
	secret, err := newBootstrapSecret()
	if err != nil {
		h.internal(w, r, err)
		return
	}
	sum := sha256.Sum256([]byte(secret))
	tokenID := uuid.New()
	var row db.InsertBootstrapTokenRow
	err = audit.Do(r.Context(), h.pool, audit.Action{
		AdminID: adminID, Action: db.AuditActionBootstrapTokenIssued,
		// Цель — сам токен, а не сервер: по target_id оператор находит строку в
		// bootstrap_tokens и из неё же читает, какому узлу что выдавали.
		TargetType: "bootstrap_token", TargetID: tokenID.String(),
		Reason:    optionalReason("", db.AuditActionBootstrapTokenIssued),
		RequestID: requestIDForAction(r),
	}, func(tx *db.Queries) error {
		created, err := tx.InsertBootstrapToken(r.Context(), db.InsertBootstrapTokenParams{
			ID: tokenID, TokenHash: sum[:], ServerID: id, CreatedBy: &adminID,
			ExpiresAt: nowUTC().Add(ttl),
		})
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
	h.write(w, r, http.StatusCreated, issuedToken{
		bootstrapRow: bootstrapRow{ID: row.ID, ServerID: row.ServerID,
			CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt},
		Token: secret,
	})
}

// listBootstrapTokens — список живых токенов сервера. Ни секрета, ни хэша в нём нет
// по построению: хэш в ответе сделал бы список словаром для подбора значения, а сам
// секрет восстановить нечем — список обязан показывать это отсутствием поля.
func (h *Handler) listBootstrapTokens(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.subject(w, r); !ok {
		return
	}
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	if _, err := h.q.ServerByID(r.Context(), id); noRows(err) {
		h.refuse(w, r, ErrServerUnknown)
		return
	} else if err != nil {
		h.internal(w, r, err)
		return
	}
	rows, err := h.q.LiveBootstrapTokensOfServer(r.Context(), id)
	if err != nil {
		h.internal(w, r, err)
		return
	}
	items := make([]bootstrapRow, 0, len(rows))
	for _, row := range rows {
		items = append(items, bootstrapRow{ID: row.ID, ServerID: id,
			CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt})
	}
	h.write(w, r, http.StatusOK, map[string]any{"bootstrap_tokens": items})
}

// revokeBootstrapToken отзывает живой токен. Ноль обновлённых строк — не успех: у
// «токена нет» и «токен уже сожжён узлом» разные продолжения, и второе требует не
// повторного отзыва, а поиска узла, который его использовал.
func (h *Handler) revokeBootstrapToken(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.subject(w, r)
	if !ok {
		return
	}
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in reasonRequest
	if !h.decodeOptional(w, r, &in) {
		return
	}
	reason, ok := h.requiredReason(w, r, in.Reason)
	if !ok {
		return
	}
	err := audit.Do(r.Context(), h.pool, audit.Action{
		AdminID: adminID, Action: db.AuditActionBootstrapTokenRevoked,
		TargetType: "bootstrap_token", TargetID: id.String(),
		Reason: reason, RequestID: requestIDForAction(r),
	}, func(tx *db.Queries) error {
		_, err := tx.RevokeBootstrapToken(r.Context(), id)
		if noRows(err) {
			return ErrTokenNotLive
		}
		return err
	})
	if err != nil {
		h.refuse(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// revokeNodeToken отрезает узел: гасит все его узловые токены, поднимает версию
// конфигурации и выводит сервер из раздачи.
//
// Две записи аудита в одной транзакции — решение, а не дублирование: «узел отрезан» и
// «набор пиеров снят» должны читаться из журнала как одно решение с одним request_id,
// а не как два действия, разнесённых по времени и, возможно, сделанных разными людьми.
func (h *Handler) revokeNodeToken(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.subject(w, r)
	if !ok {
		return
	}
	id, ok := h.pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in reasonRequest
	if !h.decodeOptional(w, r, &in) {
		return
	}
	reason, ok := h.requiredReason(w, r, in.Reason)
	if !ok {
		return
	}
	err := audit.Do(r.Context(), h.pool, audit.Action{
		AdminID: adminID, Action: db.AuditActionNodeTokenRevoked,
		TargetType: "server", TargetID: id.String(),
		Reason: reason, RequestID: requestIDForAction(r),
	}, func(tx *db.Queries) error {
		srv, err := tx.ServerByID(r.Context(), id)
		if noRows(err) {
			return ErrServerUnknown
		}
		if err != nil {
			return err
		}
		// Ноль отозванных — не ошибка: у ещё не зарегистрированного сервера отзывов
		// нет, а «отрежь узел, который ещё не приходил» — штатный шаг раскатки.
		if _, err := tx.RevokeNodeCredentialsForServer(r.Context(), id); err != nil {
			return err
		}
		if _, err := tx.BumpServerConfigVersion(r.Context(), id); err != nil {
			return err
		}
		if _, err := tx.SetServerMaintenance(r.Context(), db.SetServerMaintenanceParams{
			ID: id, MaintenanceStatus: db.MaintenanceStatusDraining,
		}); err != nil {
			if noRows(err) {
				return ErrServerUnknown
			}
			return err
		}
		// Вытеснение пишется только когда сервер был в раздачи. Повторный отзыв
		// уже выведенного узла не обязан порождать вторую запись «вытеснение
		// началось»: оно началось раньше, а журнал, повторяющий одно решение каждый
		// раз, перестаёт быть следом.
		if srv.MaintenanceStatus == db.MaintenanceStatusOnline {
			return tx.InsertAdminAudit(r.Context(), db.InsertAdminAuditParams{
				AdminID: &adminID, Action: db.AuditActionServerDrained,
				TargetType: "server", TargetID: id.String(),
				Reason: reason, RequestID: requestIDForAction(r),
			})
		}
		return nil
	})
	if err != nil {
		h.refuse(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ttlSeconds — окно жизни токена. Границы не косметика: токен на 30 секунд узел не
// успеет потратить на медленной раскатке, а токен на сутки — приглашение
// зарегистрироваться тому, кто найдёт строку в журнале деплоя.
func (h *Handler) ttlSeconds(w http.ResponseWriter, r *http.Request, v *int64) (time.Duration, bool) {
	sec := int64(defaultTTLsec)
	if v != nil {
		sec = *v
	}
	if sec < minTTLsec || sec > maxTTLsec {
		h.badField(w, r, "ttl_sec", "должна быть от "+strconv.FormatInt(minTTLsec, 10)+
			" до "+strconv.FormatInt(maxTTLsec, 10)+" секунд")
		return 0, false
	}
	return time.Duration(sec) * time.Second, true
}

// newBootstrapSecret — 32 байта crypto/rand в base64url без дополнений: та же форма,
// что у узлового токена, потому что та же длина секрета.
func newBootstrapSecret() (string, error) {
	var b [bootstrapSecretBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand отказывает только при сломанном системном entropy. Молча
		// вернуться к math/rand значило бы выдать предсказуемый секрет узлу,
		// который придёт за ним через час.
		return "", errors.New("admin: bootstrap token entropy")
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
