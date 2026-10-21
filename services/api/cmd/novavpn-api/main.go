package main

import (
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"

	"github.com/novavpn/novavpn/internal/config"
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
		return errors.New("migrations land in task 5")
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
