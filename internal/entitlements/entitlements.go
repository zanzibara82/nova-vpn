package entitlements

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/novavpn/novavpn/internal/db"
)

var ErrNoActiveSubscription = errors.New("no active subscription")

// Entitlement — то, что может спросить код: сколько устройств, какие серверы,
// сколько трафика. Платежей здесь нет (цикл D), поэтому структура читается из
// subscriptions + subscription_plans и всё.
type Entitlement struct {
	UserID            uuid.UUID
	PlanID            uuid.UUID
	Slug              string
	DeviceLimit       int
	ServerSelector    string
	TrafficQuotaBytes *int64

	// Когда подписка кончается. Профили выдаются ровно до этой отметки (задача 5):
	// право не должно пережить источник права.
	EndsAt *time.Time
}

func (e Entitlement) AllowsDevice(liveCount int) bool { return liveCount < e.DeviceLimit }

func normalize(e Entitlement) (Entitlement, error) {
	if e.DeviceLimit <= 0 {
		return e, fmt.Errorf("entitlements: plan %q has device_limit=%d", e.Slug, e.DeviceLimit)
	}
	switch e.ServerSelector {
	case "all":
	default:
		return e, fmt.Errorf("entitlements: server_selector %q is not implemented in cycle A", e.ServerSelector)
	}
	return e, nil
}

type Service struct{ q *db.Queries }

func New(q *db.Queries) *Service { return &Service{q: q} }

func (s *Service) ForUser(ctx context.Context, userID uuid.UUID) (Entitlement, error) {
	row, err := s.q.LiveSubscriptionByUser(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Entitlement{}, ErrNoActiveSubscription
	}
	if err != nil {
		return Entitlement{}, fmt.Errorf("live subscription: %w", err)
	}
	return normalize(Entitlement{
		UserID:            userID,
		PlanID:            row.PlanID,
		Slug:              row.Slug,
		DeviceLimit:       int(row.DeviceLimit),
		ServerSelector:    row.ServerSelector,
		TrafficQuotaBytes: row.TrafficQuotaBytes,
		EndsAt:            row.EndsAt,
	})
}

// GrantDefaultPlanTx вызывается при регистрации: в A у пользователя нет выбора
// тарифа, но права на устройства должны существовать с первой секунды.
// Функция, а не метод: той же выдаче нужно работать внутри транзакции регистрации
// (задача 17), где Queries другая — *db.Queries передаётся аргументом.
// ends_at берётся из plan.trial_days: два места, решающие когда кончится подписка,
// обязательно разойдутся.
func GrantDefaultPlanTx(ctx context.Context, q *db.Queries, userID uuid.UUID, slug string) error {
	plan, err := q.PlanBySlug(ctx, slug)
	if err != nil {
		return fmt.Errorf("plan %q: %w", slug, err)
	}
	var endsAt *time.Time
	if plan.TrialDays > 0 {
		e := time.Now().Add(time.Duration(plan.TrialDays) * 24 * time.Hour)
		endsAt = &e
	}
	_, err = q.InsertSubscription(ctx, db.InsertSubscriptionParams{
		ID: uuid.New(), UserID: userID, PlanID: plan.ID, EndsAt: endsAt,
	})
	return err
}
