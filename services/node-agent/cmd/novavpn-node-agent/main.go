package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/novavpn/novavpn/internal/nodeagent/api"
	"github.com/novavpn/novavpn/internal/nodeagent/runtime"
	"github.com/novavpn/novavpn/internal/nodeagent/state"
	"github.com/novavpn/novavpn/internal/nodeagent/wg"
)

var version = "dev"

const help = `Команды: novavpn-node-agent <init|enroll|run|status>
  init    создать ключ узла и вывести публичный ключ
  enroll  зарегистрировать узел; стартовый токен читается из стандартного ввода
  run     запустить цикл узла
  status  вывести сохранённые метаданные, не состояние живого туннеля
  --help  вывести справку
Секреты и дополнительные аргументы в командной строке не поддерживаются.
`

type config struct {
	Env, APIURL, StateDir, CAFile, Iface string
	AllowInsecure                        bool
	Interval                             time.Duration
}

func loadConfig(getenv func(string) string) (config, error) {
	value := func(key, fallback string) string {
		if v := getenv(key); v != "" {
			return v
		}
		return fallback
	}
	cfg := config{
		Env:      value("NOVAVPN_NODE_ENV", "prod"),
		APIURL:   getenv("NOVAVPN_NODE_API_URL"),
		StateDir: value("NOVAVPN_NODE_STATE_DIR", "/var/lib/novavpn-node"),
		CAFile:   getenv("NOVAVPN_NODE_CA_FILE"),
		Iface:    value("NOVAVPN_NODE_INTERFACE", "wg0"),
	}
	var err error
	cfg.AllowInsecure, err = strconv.ParseBool(value("NOVAVPN_NODE_ALLOW_INSECURE_API", "false"))
	if err != nil {
		return config{}, errors.New("неверная настройка NOVAVPN_NODE_ALLOW_INSECURE_API")
	}
	if cfg.AllowInsecure && cfg.Env != "dev" {
		return config{}, errors.New("TLS: NOVAVPN_NODE_ALLOW_INSECURE_API разрешена только при NOVAVPN_NODE_ENV=dev")
	}
	if cfg.Env != "dev" && cfg.Env != "prod" {
		return config{}, errors.New("неверная настройка NOVAVPN_NODE_ENV")
	}
	cfg.Interval, err = time.ParseDuration(value("NOVAVPN_NODE_POLL_INTERVAL", "25s"))
	if err != nil || cfg.Interval <= 0 {
		return config{}, errors.New("неверная настройка NOVAVPN_NODE_POLL_INTERVAL: требуется положительный интервал")
	}
	return cfg, nil
}

type nodeDevice interface {
	wg.DeviceClient
	Close() error
}

type command struct {
	stdout, stderr io.Writer
	openDevice     func() (nodeDevice, error)
	runLoop        func(context.Context, *runtime.Runner) error
}

func main() {
	if err := run(os.Args[1:], os.Getenv, os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, getenv func(string) string, stdin io.Reader) error {
	c := command{
		stdout: os.Stdout, stderr: os.Stderr,
		openDevice: func() (nodeDevice, error) { return wg.Open() },
		runLoop:    func(ctx context.Context, runner *runtime.Runner) error { return runner.Run(ctx) },
	}
	return c.run(args, getenv, stdin)
}

func (c command) run(args []string, getenv func(string) string, stdin io.Reader) error {
	if len(args) != 1 {
		return errors.New(help)
	}
	switch args[0] {
	case "--help":
		if _, err := io.WriteString(c.stdout, help); err != nil {
			return errors.New("запись справки не удалась")
		}
		return nil
	case "init", "enroll", "run", "status":
	default:
		return errors.New(help)
	}
	cfg, err := loadConfig(getenv)
	if err != nil {
		return err
	}
	store := &state.Store{Dir: cfg.StateDir}
	switch args[0] {
	case "init":
		publicKey, _, err := store.EnsureKey()
		if err != nil {
			return errors.New("инициализация ключа узла не удалась")
		}
		if _, err := fmt.Fprintf(c.stdout, "public_key %s\n%s\n", publicKey, "передайте его администратору при создании сервера"); err != nil {
			return errors.New("запись публичного ключа не удалась")
		}
		return nil
	case "enroll":
		raw, err := io.ReadAll(stdin)
		if err != nil {
			return errors.New("чтение стартового токена не удалось")
		}
		token := strings.TrimRight(string(raw), "\r\n")
		if strings.TrimSpace(token) == "" {
			return errors.New("стартовый токен не задан")
		}
		key, err := store.PrivateKey()
		if err != nil {
			return errors.New("чтение приватного ключа не удалось; сначала выполните init")
		}
		client, err := newClient(cfg)
		if err != nil {
			return err
		}
		registered, err := client.Enroll(context.Background(), token, key.PublicKey().String())
		if err != nil {
			return errors.New("регистрация узла не удалась")
		}
		if strings.TrimSpace(registered.ServerID) == "" || strings.TrimSpace(registered.NodeToken) == "" {
			return errors.New("получен неполный ответ регистрации узла")
		}
		ns := state.NodeState{ServerID: registered.ServerID, NodeToken: registered.NodeToken, TokenIssuedAt: time.Now().UTC()}
		if err := store.Save(ns); err != nil {
			return errors.New("запись состояния регистрации не удалась")
		}
		return nil
	case "status", "run":
		ns, err := store.Load()
		if err != nil {
			return errors.New("чтение состояния узла не удалось")
		}
		if strings.TrimSpace(ns.ServerID) == "" || strings.TrimSpace(ns.NodeToken) == "" {
			return errors.New("узел не инициализирован")
		}
		if args[0] == "status" {
			if _, err := fmt.Fprintf(c.stdout, "server_id %s\napplied.config_version %d\napplied.peers %d\napplied.applied_at %s\ntoken_issued_at %s\n",
				ns.ServerID, ns.Applied.ConfigVersion, ns.Applied.Peers,
				ns.Applied.AppliedAt.UTC().Format(time.RFC3339), ns.TokenIssuedAt.UTC().Format(time.RFC3339)); err != nil {
				return errors.New("запись сохранённых метаданных не удалась")
			}
			return nil
		}
		if _, err := store.PrivateKey(); err != nil {
			return errors.New("чтение приватного ключа не удалось; сначала выполните init")
		}
		client, err := newClient(cfg)
		if err != nil {
			return err
		}
		client.SetToken(ns.NodeToken)
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return c.runNode(ctx, cfg, store, client)
	}
	return errors.New(help)
}

func newClient(cfg config) (*api.Client, error) {
	if cfg.APIURL == "" {
		return nil, errors.New("не задана настройка NOVAVPN_NODE_API_URL")
	}
	client, err := api.New(api.Config{BaseURL: cfg.APIURL, CAFile: cfg.CAFile, Env: cfg.Env, AllowInsecure: cfg.AllowInsecure})
	if err != nil {
		return nil, errors.New("настройка API/TLS не удалась: проверьте NOVAVPN_NODE_API_URL и NOVAVPN_NODE_CA_FILE")
	}
	return client, nil
}

func (c command) runNode(ctx context.Context, cfg config, store *state.Store, client *api.Client) (result error) {
	device, err := c.openDevice()
	if err != nil {
		return errors.New("открытие управляющего сокета узла не удалось")
	}
	defer func() {
		if err := device.Close(); err != nil {
			result = errors.Join(result, errors.New("закрытие управляющего сокета узла не удалось"))
		}
	}()
	applier := &wg.Applier{Link: wg.Netlink{}, Device: device, Iface: cfg.Iface}
	runner := &runtime.Runner{
		API: client, Applier: applier, Store: store,
		Iface: cfg.Iface, Interval: cfg.Interval, TokenTTL: 24 * time.Hour,
		Version: version, Now: time.Now, Log: slog.New(slog.NewJSONHandler(c.stderr, nil)),
	}
	if err := c.runLoop(ctx, runner); err != nil && !errors.Is(err, context.Canceled) {
		return errors.New("цикл узла завершился с ошибкой")
	}
	return nil
}
