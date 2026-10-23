package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RunInTx выполняет fn в одном транзакционном контексте. sqlc-методы вызываются
// через q.WithTx(tx), поэтому транзакция — единственный способ собрать
// «advisory lock + count + insert» в один атомарный шаг.
func RunInTx(ctx context.Context, pool *pgxpool.Pool, fn func(*Queries) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) // no-op после Commit
	if err := fn(New(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
