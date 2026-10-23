package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/novavpn/novavpn/internal/config"
	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/db/migrate"
	"github.com/novavpn/novavpn/internal/entitlements"
	"github.com/novavpn/novavpn/services/api"
)

func main() {
	if err := run(os.Args[1:], os.Getenv); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(args []string, getenv func(string) string) error {
	fs := flag.NewFlagSet("novavpn-api", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cmd := fs.Arg(0)
	cfg, err := config.Load(getenv)
	if err != nil {
		return err
	}
	switch cmd {
	case "serve":
		return serve(cfg)
	case "migrate":
		if fs.NArg() < 2 {
			return errors.New("usage: novavpn-api migrate up|all|version")
		}
		ctx := context.Background()
		switch fs.Arg(1) {
		case "up":
			v, err := migrate.Up(ctx, cfg.DatabaseURL)
			fmt.Println("version", v)
			return err
		case "all":
			v, err := migrate.Steps(ctx, cfg.DatabaseURL, -1<<31)
			fmt.Println("reverted to", v)
			return err
		case "version":
			v, err := migrate.Steps(ctx, cfg.DatabaseURL, 0)
			fmt.Println("version", v)
			return err
		default:
			return errors.New("usage: novavpn-api migrate up|all|version")
		}
	case "":
		return errors.New("usage: novavpn-api serve|migrate <up|all>")
	default:
		return errors.New("usage: novavpn-api serve|migrate <up|all>")
	}
}

func serve(cfg config.Config) error {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Pool(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
	defer rdb.Close()

	handler := api.NewRouter(api.Deps{
		Cfg: cfg, Pool: pool, RDB: rdb,
		Ent: entitlements.New(db.New(pool)), Log: log,
	})
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	log.Info("listening", "addr", cfg.ListenAddr, "env", cfg.Env)

	select {
	case err := <-errCh:
		return fmt.Errorf("listen: %w", err)
	case <-ctx.Done():
	}

	// Активные соединения дозаписывают ответ: kill switch у HTTP-сервера без
	// Shutdown означает «оборви чужую выдачу токенов на середине тела».
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Info("stopped")
	return nil
}
