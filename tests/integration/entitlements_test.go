//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/entitlements"
)

func TestEntitlementsForUser(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	q := db.New(pool(t))
	svc := entitlements.New(q)

	// Пользователь без подписки → явная ошибка, а не дефолтный лимит.
	userless := seedUserWithoutPlan(t, ctx, q)
	if _, err := svc.ForUser(ctx, userless); err == nil || !errors.Is(err, entitlements.ErrNoActiveSubscription) {
		t.Fatalf("ForUser(no subscription) = %v, want ErrNoActiveSubscription", err)
	}

	user := seedUser(t, ctx, q, true) // создаёт подписку internal-default (см. задачу 12, helpers)
	e, err := svc.ForUser(ctx, user)
	if err != nil {
		t.Fatalf("ForUser: %v", err)
	}
	if e.Slug != "internal-default" || e.DeviceLimit != 3 || e.ServerSelector != "all" {
		t.Errorf("unexpected entitlement: %+v", e)
	}
	if e.TrafficQuotaBytes != nil {
		t.Errorf("internal-default must be unlimited, quota = %d", *e.TrafficQuotaBytes)
	}
	if !e.AllowsDevice(2) || e.AllowsDevice(3) {
		t.Error("device counting is wrong at the boundary")
	}
}

func TestUnknownSelectorIsAnErrorNotATicket(t *testing.T) {
	ctx := context.Background()
	q := db.New(pool(t))
	slug := "selector-test-" + uuid.NewString()[:8]
	if _, err := q.InsertPlan(ctx, db.InsertPlanParams{
		ID: uuid.New(), Slug: slug,
		DeviceLimit: 5, ServerSelector: "country=DE",
	}); err != nil {
		t.Fatalf("InsertPlan: %v", err)
	}
	user := seedUserWithPlan(t, ctx, q, slug)
	if _, err := entitlements.New(q).ForUser(ctx, user); err == nil {
		t.Fatal("selector 'country=DE' accepted in cycle A")
	}
}

// GrantDefaultPlanTx обязан заполнить starts_at: нулевое время (год 1) ломает выбор
// «последняя подписка» и отчётность цикла D. source выводится из trial_days: у
// internal-default пробного срока нет, значит метка manual, а не trial.
func TestGrantDefaultPlanSetsStartAndSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	q := db.New(pool(t))
	user := seedUserWithoutPlan(t, ctx, q)
	before := time.Now().Add(-time.Second)
	if err := entitlements.GrantDefaultPlanTx(ctx, q, user, "internal-default"); err != nil {
		t.Fatalf("GrantDefaultPlanTx: %v", err)
	}
	var starts time.Time
	var source string
	if err := pool(t).QueryRow(ctx,
		`SELECT starts_at, source::text FROM subscriptions WHERE user_id = $1`, user,
	).Scan(&starts, &source); err != nil {
		t.Fatalf("subscription row: %v", err)
	}
	if starts.Before(before) || starts.After(time.Now().Add(time.Second)) {
		t.Errorf("starts_at = %v, want сейчас", starts)
	}
	if source != "manual" {
		t.Errorf("source = %q, want manual", source)
	}
}
