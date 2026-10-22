package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Pool(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("database url: %w", err)
	}
	cfg.MaxConns = 8
	cfg.MaxConnLifetime = time.Hour
	return pgxpool.NewWithConfig(ctx, cfg)
}
