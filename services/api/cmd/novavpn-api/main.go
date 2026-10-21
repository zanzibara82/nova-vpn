package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/novavpn/novavpn/internal/config"
	"github.com/novavpn/novavpn/internal/db/migrate"
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
	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	slog.Info("listening", "addr", cfg.ListenAddr, "env", cfg.Env)
	srv := &http.Server{Addr: cfg.ListenAddr, Handler: mux, ReadHeaderTimeout: 5e9}
	return srv.ListenAndServe()
}
