//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/db"
)

// Один пул на весь прогон: интеграционные тесты их создают десятки, а
// pg_max_connections на dev-стеке конечен.
var sharedPool *pgxpool.Pool

func pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if sharedPool == nil {
		p, err := db.Pool(context.Background(), databaseURL(t))
		if err != nil {
			t.Fatalf("pool: %v", err)
		}
		sharedPool = p
	}
	return sharedPool
}

func bytes32ForTests() []byte { return []byte("integration-secret-0000000000000000") }

func redisClient(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("NOVAVPN_REDIS_ADDR")
	if addr == "" {
		t.Skip("NOVAVPN_REDIS_ADDR is not set; run `make up-dev` first")
	}
	c := redis.NewClient(&redis.Options{Addr: addr})
	if err := c.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("redis at %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func seedUser(t *testing.T, ctx context.Context, q *db.Queries, withPlan bool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	hash, err := auth.HashPassword("integration-password-123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if _, err := q.InsertUser(ctx, db.InsertUserParams{
		ID: id, Email: "seed-" + id.String()[:8] + "@novavpn.test",
		PasswordHash: hash, Locale: "ru",
	}); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if withPlan {
		if _, err := q.InsertSubscription(ctx, db.InsertSubscriptionParams{
			ID:       uuid.New(),
			UserID:   id,
			PlanID:   uuid.MustParse("00000000-0000-4000-8000-000000000a01"),
			StartsAt: time.Now(),
		}); err != nil {
			t.Fatalf("InsertSubscription: %v", err)
		}
	}
	return id
}

func seedUserWithoutPlan(t *testing.T, ctx context.Context, q *db.Queries) uuid.UUID {
	return seedUser(t, ctx, q, false)
}

func seedUserWithPlan(t *testing.T, ctx context.Context, q *db.Queries, slug string) uuid.UUID {
	t.Helper()
	id := seedUser(t, ctx, q, false)
	planID, err := q.PlanIDBySlug(ctx, slug)
	if err != nil {
		t.Fatalf("PlanIDBySlug: %v", err)
	}
	if _, err := q.InsertSubscription(ctx, db.InsertSubscriptionParams{
		ID:       uuid.New(),
		UserID:   id,
		PlanID:   planID,
		StartsAt: time.Now(),
	}); err != nil {
		t.Fatalf("InsertSubscription: %v", err)
	}
	return id
}
