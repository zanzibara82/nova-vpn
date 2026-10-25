package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"

	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/config"
	"github.com/novavpn/novavpn/internal/connections"
	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/db/migrate"
	"github.com/novavpn/novavpn/internal/entitlements"
	"github.com/novavpn/novavpn/services/api"
)

func main() {
	if err := run(os.Args[1:], os.Getenv, readStdin); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// readStdin — источник пароля для `admin create`. Пароль не берётся ни из argv
// (виден в ps и в истории shell'а), ни из env-файла: это единственный фактор,
// который у администратора не отозвать.
func readStdin() ([]byte, error) {
	return io.ReadAll(os.Stdin)
}

func run(args []string, getenv func(string) string, input func() ([]byte, error)) error {
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
	case "admin":
		return createAdmin(cfg, fs.Args()[1:], input)
	case "":
		return errors.New("usage: novavpn-api serve|migrate <up|all>")
	default:
		return errors.New("usage: novavpn-api serve|migrate <up|all>")
	}
}

// createAdmin — первый администратор в пустой базе. Аудит-записи у этого пути нет
// намеренно: admin_audit_logs.admin_id — внешний ключ на admin_users, и «создал сам
// себя» нечем записать до появления строки. След остаётся строкой stdout и created_at.
func createAdmin(cfg config.Config, args []string, input func() ([]byte, error)) error {
	fs := flag.NewFlagSet("admin", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.Arg(0) != "create" || fs.Arg(1) == "" {
		return errors.New("usage: novavpn-api admin create <email>")
	}
	email := strings.TrimSpace(fs.Arg(1))

	raw, err := input()
	if err != nil {
		return fmt.Errorf("read password from stdin: %w", err)
	}
	// Хвостовой перевод строки — от `echo`: обрезан он, а не пробелы внутри,
	// потому что пробел в пароле — часть пароля.
	password := strings.TrimRight(string(raw), "\r\n")
	hash, err := auth.HashPassword(password)
	if err != nil {
		return fmt.Errorf("password: %w", err)
	}

	ctx := context.Background()
	pool, err := db.Pool(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	row, err := db.New(pool).InsertAdminUser(ctx, db.InsertAdminUserParams{
		ID: uuid.New(), Email: email, PasswordHash: hash,
	})
	if err != nil {
		// На admin_users UNIQUE только email, поэтому код 23505 здесь означает
		// ровно одно — и скрипту раскатки нужен ненулевой выход, а не молчаливый успех.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("администратор с таким email уже есть: %s", email)
		}
		return err
	}
	fmt.Printf("id %s\nemail %s\n", row.ID, row.Email)
	return nil
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

	go connections.Run(ctx, connections.NewStore(pool), log, connections.DefaultSweepInterval)

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
