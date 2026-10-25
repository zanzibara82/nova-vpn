// Package audit — единственная точка записи административного журнала (спецификация §3:
// «у права есть след»). Ответственность пакета: не давать изменить что-то, не записав
// причину, а не «уметь писать в admin_audit_logs».
package audit

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/novavpn/novavpn/internal/db"
)

// Окно причины совпадает с CHECK admin_audit_reason (миграция 0003). Проверка в Go нужна
// не для красоты: без неё запрос с причиной из двух символов получил бы 500 из-за отката
// транзакции вместо 400 на собственное поле.
const (
	minReason = 3
	maxReason = 500
)

var ErrReasonRequired = errors.New("audit: reason must be 3..500 characters")

// Action — действие с обязательной причиной. TargetID — текст, а не uuid: целями бывают
// и сервер, и пользователь, и bootstrap-токен, и различаются они только полем target_type.
type Action struct {
	AdminID    uuid.UUID
	Action     db.AuditAction
	TargetType string
	TargetID   string
	Reason     string
	RequestID  string
}

// Do исполняет изменение и его запись в аудит одной транзакцией. «Изменили, но не
// записали» — состояние, которого не должно существовать: ТЗ §9 требует причину у каждого
// действия, а без атомарности её нет ровно тогда, когда она нужнее всего (отказ в момент
// отзыва). mutate получает транзакционные запросы и не имеет права трогать pool.
func Do(ctx context.Context, pool *pgxpool.Pool, a Action, mutate func(*db.Queries) error) error {
	if err := check(a); err != nil {
		return err
	}
	return db.RunInTx(ctx, pool, func(q *db.Queries) error {
		if err := mutate(q); err != nil {
			return err
		}
		return q.InsertAdminAudit(ctx, db.InsertAdminAuditParams{
			AdminID:    &a.AdminID,
			Action:     a.Action,
			TargetType: a.TargetType,
			TargetID:   a.TargetID,
			Reason:     a.Reason,
			RequestID:  a.RequestID,
		})
	})
}

func check(a Action) error {
	n := utf8.RuneCountInString(a.Reason)
	if n < minReason || n > maxReason {
		return fmt.Errorf("%w: got %d", ErrReasonRequired, n)
	}
	if a.AdminID == uuid.Nil {
		return errors.New("audit: action without subject")
	}
	if a.RequestID == "" || a.TargetType == "" || a.TargetID == "" {
		return errors.New("audit: action without request id or target")
	}
	return nil
}
