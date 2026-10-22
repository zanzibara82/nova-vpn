//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

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
