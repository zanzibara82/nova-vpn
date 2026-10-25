package connections

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/novavpn/novavpn/internal/db"
)

// Окна «жизни без клиента». Оба числа — решение плана, а не строка из ТЗ:
// спецификация §7.2 описывает отзыв по инициативе пользователя, а что делать с
// выданным и забытым профилем — не говорит.
const (
	// DefaultSweepInterval — как часто метать просрочку. Час: DesiredTTL в месяцах,
	// и опаздывать на час с profile_expired ничего не стоит, а чаще — значит гонять
	// три DELETE'а по полным таблицам на каждом такте.
	DefaultSweepInterval = time.Hour

	// DormantAfter — профиль, под которым ни разу не наблюдали handshake, живёт
	// столько. Смысл числа: «выдал и забыл» становится мусором в desired set, а
	// каждый лишний пиер — это строка в конфиге узла и адрес, занявший пул.
	DormantAfter = 7 * 24 * time.Hour
)

// Retention — сколько строк метла убрала из каждого стола. Это не «для статистики»:
// оператор по числам судит, метла работает или молча падает каждый такт.
type Retention struct {
	EventsDeleted int64
	IPsCleared    int64
	KeysPurged    int64
}

type Report struct {
	Expired   int
	Dormant   int
	Stale     int
	Retention Retention
}

// Store — то, что делает метель. Интерфейс нужен не для «слоя»: порождать просроченный
// профиль в проде можно только временем, а ждать его в тесте нельзя, поэтому тест
// подставляет хранилище, а интеграционный прогон играет настоящей БД (шаг 7 этой задачи).
type Store interface {
	SweepExpired(ctx context.Context, now time.Time) (int, error)
	SweepDormant(ctx context.Context, now time.Time) (int, error)
	SweepStale(ctx context.Context, now time.Time) (int, error)
	SweepRetention(ctx context.Context, now time.Time) (Retention, error)
}

type pgStore struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) Store { return &pgStore{pool: pool} }

// sweepAll метёт четыре вида работы и не даёт одному виду остановить остальные.
// Причина не в вежливости: retention — самый дорогой и самый «внешний» шаг (полные
// таблицы), и его падение из-за отвалившегося соединения не имеет права означать
// «просроченный профиль ещё час сидел в desired set».
func sweepAll(ctx context.Context, st Store, log *slog.Logger, now time.Time) Report {
	var r Report
	n, err := st.SweepExpired(ctx, now)
	if err != nil {
		log.Error("sweep expired", "err", err)
	} else {
		r.Expired = n
	}
	n, err = st.SweepDormant(ctx, now)
	if err != nil {
		log.Error("sweep dormant", "err", err)
	} else {
		r.Dormant = n
	}
	n, err = st.SweepStale(ctx, now)
	if err != nil {
		log.Error("stale mark", "err", err)
	} else {
		r.Stale = n
	}
	ret, err := st.SweepRetention(ctx, now)
	if err != nil {
		log.Error("retention sweep", "err", err)
	} else {
		r.Retention = ret
	}
	if r.Expired+r.Dormant+r.Stale != 0 || r.Retention != (Retention{}) {
		log.Info("sweep", "expired", r.Expired, "dormant", r.Dormant,
			"stale", r.Stale, "events_deleted", r.Retention.EventsDeleted,
			"ips_cleared", r.Retention.IPsCleared, "keys_purged", r.Retention.KeysPurged)
	}
	return r
}

// Run — тактовый цикл. Первый проход сразу после старта: профиль мог протухнуть,
// пока API был выключен, а час молчания desired set с уже снятым доступом — это
// обещание (§7.2 «узел снимает пиера»), которое никто не выполнил.
func Run(ctx context.Context, st Store, log *slog.Logger, interval time.Duration) {
	sweepAll(ctx, st, log, time.Now())
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweepAll(ctx, st, log, time.Now())
		}
	}
}

// SweepExpired — одна транзакция на профиль. Общая транзакция держала бы advisory-замки
// всех серверов сразу, и выдача встала бы на всё время прохода; по профилю замок живёт
// миллисекунды. Порядок выборки (ORDER BY p.id) один и тот же, поэтому две реплики
// метлы не входят в клинч.
func (s *pgStore) SweepExpired(ctx context.Context, _ time.Time) (int, error) {
	rows, err := db.New(s.pool).ExpiredActiveProfiles(ctx)
	if err != nil {
		return 0, fmt.Errorf("sweeper: выборка просроченных профилей: %w", err)
	}
	swept := 0
	for _, row := range rows {
		done := false
		err := db.RunInTx(ctx, s.pool, func(q *db.Queries) error {
			if _, err := q.MarkProfileExpired(ctx, row.ID); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					// Профиль успели отозвать пользователь или другая метла: это не
					// поломка, и bump с событием ему уже не нужны.
					return nil
				}
				return fmt.Errorf("sweeper: пометка профиля %v просроченным: %w", row.ID, err)
			}
			if err := q.ReleaseAddressByProfile(ctx, &row.ID); err != nil {
				return fmt.Errorf("sweeper: освобождение адреса профиля %v: %w", row.ID, err)
			}
			if _, err := q.BumpServerConfigVersion(ctx, row.ServerID); err != nil {
				return fmt.Errorf("sweeper: версия конфига сервера %v: %w", row.ServerID, err)
			}
			if err := q.InsertConnectionEvent(ctx, db.InsertConnectionEventParams{
				UserID: &row.UserID, DeviceID: &row.DeviceID, ServerID: &row.ServerID,
				Event: db.EventTypeProfileExpired, Detail: []byte(`{}`),
			}); err != nil {
				return fmt.Errorf("sweeper: событие просрочки профиля %v: %w", row.ID, err)
			}
			done = true
			return nil
		})
		if err != nil {
			return swept, err
		}
		if done {
			swept++
		}
	}
	return swept, nil
}

// SweepDormant снимает профиль, под которым ни разу не было handshake. Статус
// 'revoked', а не 'expired': это решение, а не истечение времени, и revoked_at обязан
// это показать.
func (s *pgStore) SweepDormant(ctx context.Context, now time.Time) (int, error) {
	rows, err := db.New(s.pool).DormantActiveProfiles(ctx, now.Add(-DormantAfter))
	if err != nil {
		return 0, fmt.Errorf("sweeper: выборка спящих профилей: %w", err)
	}
	swept := 0
	for _, row := range rows {
		done := false
		err := db.RunInTx(ctx, s.pool, func(q *db.Queries) error {
			if _, err := q.RevokeProfile(ctx, row.ID); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil
				}
				return fmt.Errorf("sweeper: отзыв спящего профиля %v: %w", row.ID, err)
			}
			if err := q.ReleaseAddressByProfile(ctx, &row.ID); err != nil {
				return fmt.Errorf("sweeper: освобождение адреса профиля %v: %w", row.ID, err)
			}
			if _, err := q.BumpServerConfigVersion(ctx, row.ServerID); err != nil {
				return fmt.Errorf("sweeper: версия конфига сервера %v: %w", row.ServerID, err)
			}
			if err := q.InsertConnectionEvent(ctx, db.InsertConnectionEventParams{
				UserID: &row.UserID, DeviceID: &row.DeviceID, ServerID: &row.ServerID,
				Event: db.EventTypeProfileRevoked, Detail: []byte(`{"reason":"dormant"}`),
			}); err != nil {
				return fmt.Errorf("sweeper: событие отзыва профиля %v: %w", row.ID, err)
			}
			done = true
			return nil
		})
		if err != nil {
			return swept, err
		}
		if done {
			swept++
		}
	}
	return swept, nil
}

// SweepStale помечает зависшие узлы и пишет событие ровно на переход ok → stale.
// Условие status = 'ok' живёт в SQL: без него за сутки на одном замолчавшем узле
// накопилось бы 24 одинаковые записи, и «узел завис» стало бы шумом.
func (s *pgStore) SweepStale(ctx context.Context, _ time.Time) (int, error) {
	var n int
	err := db.RunInTx(ctx, s.pool, func(q *db.Queries) error {
		ids, err := q.MarkStaleHealth(ctx)
		if err != nil {
			return fmt.Errorf("sweeper: пометка зависших узлов: %w", err)
		}
		for _, id := range ids {
			if err := q.InsertConnectionEvent(ctx, db.InsertConnectionEventParams{
				ServerID: &id, Event: db.EventTypeNodeStale, Detail: []byte(`{}`),
			}); err != nil {
				return fmt.Errorf("sweeper: событие node_stale узла %v: %w", id, err)
			}
		}
		n = len(ids)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// SweepRetention чистит три независимых стола без общей транзакции: «два очистились,
// третий упал» для оператора лучше, чем «ничего не очистилось, но атомарно». Границы
// окон уже написаны в SQL задачи 1, поэтому now сюда не приходит — второго источника
// времени не появляется.
func (s *pgStore) SweepRetention(ctx context.Context, _ time.Time) (Retention, error) {
	q := db.New(s.pool)
	var r Retention
	n, err := q.DeleteOldConnectionEvents(ctx)
	if err != nil {
		return r, fmt.Errorf("sweeper: retention событий: %w", err)
	}
	r.EventsDeleted = n
	n, err = q.NullOldRefreshIPs(ctx)
	if err != nil {
		return r, fmt.Errorf("sweeper: retention адресов refresh-семей: %w", err)
	}
	r.IPsCleared = n
	n, err = q.PurgeOldIdempotencyKeys(ctx)
	if err != nil {
		return r, fmt.Errorf("sweeper: retention ключей идемпотентности: %w", err)
	}
	r.KeysPurged = n
	return r, nil
}
