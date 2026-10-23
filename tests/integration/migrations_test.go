//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/novavpn/novavpn/internal/db/migrate"
)

func databaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("NOVAVPN_DATABASE_URL")
	if url == "" {
		t.Skip("NOVAVPN_DATABASE_URL is not set; run `make up-dev` first")
	}
	return url
}

func TestMigrationsUpToDownToUp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Схема сейчас будет пересоздана: закэшированные prepared-стейтменты общего
	// пула устареют («cached plan must not change result type»). Пул
	// инвалидируется — следующий тест создаст новый.
	t.Cleanup(func() {
		if sharedPool != nil {
			sharedPool.Close()
			sharedPool = nil
		}
	})

	if _, err := migrate.Steps(ctx, databaseURL(t), -1<<31); err != nil {
		t.Fatalf("migrate down all: %v", err)
	}
	v, err := migrate.Up(ctx, databaseURL(t))
	if err != nil {
		t.Fatalf("first up: %v", err)
	}
	v2, err := migrate.Up(ctx, databaseURL(t))
	if err != nil {
		t.Fatalf("second up (must be no-op): %v", err)
	}
	if v != v2 {
		t.Errorf("version changed on no-op up: %d -> %d", v, v2)
	}

	conn, err := pgx.Connect(ctx, databaseURL(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)
	for _, table := range []string{"users", "devices", "vpn_profiles", "tunnel_addresses", "subscription_plans"} {
		var exists bool
		err := conn.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1)`,
			table).Scan(&exists)
		if err != nil || !exists {
			t.Errorf("table %q missing after up: err=%v exists=%v", table, err, exists)
		}
	}
	// Предзаполненный план обязан дожить до конца прогона.
	var plans int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM subscription_plans WHERE slug='internal-default'`).Scan(&plans); err != nil || plans != 1 {
		t.Errorf("internal-default plan: count=%d err=%v", plans, err)
	}
	// down → up не должен оставить висящих типов: иначе 0001/0002/0003 разойдутся.
	var types int
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM pg_type WHERE typcategory='E' AND typname IN ('user_status','device_platform','profile_status','peer_state')`).Scan(&types); err != nil || types != 4 {
		t.Errorf("enum types after up: got %d want 4 (err=%v)", types, err)
	}
}
