package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/novavpn/novavpn/internal/nodeagent/api"
	"github.com/novavpn/novavpn/internal/nodeagent/runtime"
	"github.com/novavpn/novavpn/internal/nodeagent/state"
	"github.com/novavpn/novavpn/internal/nodeagent/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func secret(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal("не удалось создать тестовый секрет")
	}
	return hex.EncodeToString(raw)
}

func noLeaks(t *testing.T, out, stderr string, err error, secrets ...string) {
	t.Helper()
	text := out + stderr
	if err != nil {
		text += err.Error()
	}
	for _, s := range secrets {
		if s != "" && strings.Contains(text, s) {
			t.Fatal("диагностика раскрыла секрет")
		}
	}
}

func localCommand(t *testing.T) (command, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	out, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	return command{
		stdout: out, stderr: stderr,
		openDevice: func() (nodeDevice, error) {
			t.Fatal("неожиданное обращение к ядру")
			return nil, nil
		},
		runLoop: func(context.Context, *runtime.Runner) error {
			t.Fatal("неожиданный запуск цикла")
			return nil
		},
	}, out, stderr
}

func envFor(dir string) map[string]string {
	return map[string]string{"NOVAVPN_NODE_STATE_DIR": dir}
}

func invoke(c command, args []string, env map[string]string, input io.Reader) error {
	return c.run(args, func(k string) string { return env[k] }, input)
}

type brokenIO struct{ err error }

func (b brokenIO) Read([]byte) (int, error)  { return 0, b.err }
func (b brokenIO) Write([]byte) (int, error) { return 0, b.err }

type forbiddenReader struct{ t *testing.T }

func (r forbiddenReader) Read([]byte) (int, error) {
	r.t.Fatal("неожиданное чтение стандартного ввода")
	return 0, io.EOF
}

func TestHelpRejectsArgumentsWithoutSideEffects(t *testing.T) {
	value := secret(t)
	for _, tc := range []struct {
		name    string
		args    []string
		success bool
	}{
		{"empty", nil, false}, {"unknown", []string{value}, false},
		{"extra", []string{"enroll", value}, false}, {"extra_help", []string{"--help", value}, false},
		{"help", []string{"--help"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, out, stderr := localCommand(t)
			err := c.run(tc.args, func(string) string { t.Fatal("справка читает окружение"); return "" }, forbiddenReader{t})
			if (err == nil) != tc.success {
				t.Fatal("неверный результат справки")
			}
			text := out.String()
			if err != nil {
				text += err.Error()
			}
			for _, name := range []string{"init", "enroll", "run", "status"} {
				if !strings.Contains(text, name) {
					t.Fatalf("нет команды %s в справке", name)
				}
			}
			if tc.success && out.Len() == 0 {
				t.Fatal("справка не записана в стандартный вывод")
			}
			noLeaks(t, out.String(), stderr.String(), err, value)
		})
	}
}

func TestConfigDefaultsAndExplicitValues(t *testing.T) {
	keys := map[string]bool{}
	cfg, err := loadConfig(func(k string) string { keys[k] = true; return "" })
	want := config{Env: "prod", StateDir: "/var/lib/novavpn-node", Iface: "wg0", Interval: 25 * time.Second}
	if err != nil || cfg != want {
		t.Fatal("неверные значения по умолчанию")
	}
	allowed := map[string]bool{}
	for _, k := range []string{"ENV", "API_URL", "STATE_DIR", "CA_FILE", "ALLOW_INSECURE_API", "INTERFACE", "POLL_INTERVAL"} {
		allowed["NOVAVPN_NODE_"+k] = true
	}
	if !reflect.DeepEqual(keys, allowed) {
		t.Fatal("прочитан неверный набор имён окружения")
	}
	env := map[string]string{
		"NOVAVPN_NODE_ENV": "dev", "NOVAVPN_NODE_API_URL": "https://example.invalid",
		"NOVAVPN_NODE_STATE_DIR": "/tmp/node", "NOVAVPN_NODE_CA_FILE": "/tmp/ca.pem",
		"NOVAVPN_NODE_ALLOW_INSECURE_API": "1", "NOVAVPN_NODE_INTERFACE": "wg7", "NOVAVPN_NODE_POLL_INTERVAL": "1250ms",
	}
	cfg, err = loadConfig(func(k string) string { return env[k] })
	want = config{Env: "dev", APIURL: "https://example.invalid", StateDir: "/tmp/node", CAFile: "/tmp/ca.pem", AllowInsecure: true, Iface: "wg7", Interval: 1250 * time.Millisecond}
	if err != nil || cfg != want {
		t.Fatal("явные значения конфигурации потеряны")
	}
	for _, value := range []string{"true", "TRUE", "True", "1", "false", "FALSE", "False", "0"} {
		env["NOVAVPN_NODE_ALLOW_INSECURE_API"] = value
		cfg, err = loadConfig(func(k string) string { return env[k] })
		if err != nil || cfg.AllowInsecure != (value == "1" || strings.EqualFold(value, "true")) {
			t.Fatal("не соблюдён стандартный разбор булева значения")
		}
	}
}

func TestConfigRejectsInvalidValuesSafely(t *testing.T) {
	value := secret(t)
	for _, tc := range []struct{ key, value string }{
		{"ENV", value}, {"ENV", "DEV"}, {"ALLOW_INSECURE_API", value},
		{"POLL_INTERVAL", value}, {"POLL_INTERVAL", "0s"}, {"POLL_INTERVAL", "-1s"},
	} {
		t.Run(tc.key+"_"+strings.ReplaceAll(tc.value[:1], "-", "negative"), func(t *testing.T) {
			key := "NOVAVPN_NODE_" + tc.key
			_, err := loadConfig(func(k string) string {
				if k == key {
					return tc.value
				}
				return ""
			})
			if err == nil || !strings.Contains(err.Error(), key) {
				t.Fatal("нет безопасного имени ошибочной настройки")
			}
			noLeaks(t, "", "", err, tc.value)
		})
	}
}

func TestInsecureRejectedForEveryCommandAndLegacyEnvIgnored(t *testing.T) {
	for _, name := range []string{"init", "enroll", "run", "status"} {
		t.Run(name, func(t *testing.T) {
			c, out, stderr := localCommand(t)
			env := envFor(filepath.Join(t.TempDir(), "unused"))
			env["NOVAVPN_NODE_ALLOW_INSECURE_API"] = "true"
			env["NOVAVPN_ENV"] = "dev"
			env["NOVAVPN_API_CA_FILE"] = secret(t)
			err := invoke(c, []string{name}, env, forbiddenReader{t})
			if err == nil || !strings.Contains(err.Error(), "TLS") {
				t.Fatal("разрешено ослабление TLS вне режима разработки")
			}
			if _, err := os.Stat(env["NOVAVPN_NODE_STATE_DIR"]); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("отказ создал состояние")
			}
			noLeaks(t, out.String(), stderr.String(), err, env["NOVAVPN_API_CA_FILE"])
		})
	}
}

func TestInitExactOutputStableKeyAndPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "node")
	c, out, stderr := localCommand(t)
	env := envFor(dir)
	env["NOVAVPN_NODE_CA_FILE"] = filepath.Join(dir, "absent-ca")
	env["NOVAVPN_NODE_API_URL"] = "%"
	if err := invoke(c, []string{"init"}, env, forbiddenReader{t}); err != nil {
		t.Fatal("инициализация не удалась")
	}
	store := &state.Store{Dir: dir}
	key, err := store.PrivateKey()
	if err != nil {
		t.Fatal("ключ не записан")
	}
	want := "public_key " + key.PublicKey().String() + "\n" + "передайте его администратору при создании сервера\n"
	if out.String() != want || stderr.Len() != 0 {
		t.Fatal("неверный формат инициализации")
	}
	noLeaks(t, out.String(), stderr.String(), nil, key.String())
	before, _ := os.ReadFile(filepath.Join(dir, "node.key"))
	out.Reset()
	if err := invoke(c, []string{"init"}, env, forbiddenReader{t}); err != nil {
		t.Fatal("повторная инициализация не удалась")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "node.key"))
	if !bytes.Equal(before, after) || out.String() != want {
		t.Fatal("повторная инициализация изменила ключ")
	}
	for path, mode := range map[string]os.FileMode{dir: 0o700, filepath.Join(dir, "node.key"): 0o600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatal("неверные права временного состояния")
		}
	}
}

func TestInitDoesNotReplaceCorruptKey(t *testing.T) {
	dir := t.TempDir()
	value := secret(t)
	path := filepath.Join(dir, "node.key")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal("не удалось создать повреждённый ключ")
	}
	c, out, stderr := localCommand(t)
	err := invoke(c, []string{"init"}, envFor(dir), forbiddenReader{t})
	if err == nil {
		t.Fatal("повреждённый ключ принят")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != value {
		t.Fatal("повреждённый ключ заменён")
	}
	noLeaks(t, out.String(), stderr.String(), err, value)
}

func registeredStore(t *testing.T) (*state.Store, state.NodeState) {
	t.Helper()
	s := &state.Store{Dir: t.TempDir()}
	if _, _, err := s.EnsureKey(); err != nil {
		t.Fatal("не удалось создать ключ")
	}
	ns := state.NodeState{ServerID: "node-17", NodeToken: secret(t), TokenIssuedAt: time.Date(2026, 10, 20, 12, 30, 0, 0, time.FixedZone("test", 3*3600)), Applied: state.Applied{ConfigVersion: 42, Peers: 3, ETag: "\"42\"", AppliedAt: time.Date(2026, 10, 21, 13, 40, 0, 0, time.FixedZone("test", 3*3600))}}
	if err := s.Save(ns); err != nil {
		t.Fatal("не удалось записать тестовое состояние")
	}
	return s, ns
}

func TestStatusExactSavedMetadataWithoutAPIOrKey(t *testing.T) {
	s, ns := registeredStore(t)
	key, _ := s.PrivateKey()
	if err := os.Remove(filepath.Join(s.Dir, "node.key")); err != nil {
		t.Fatal("не удалось убрать тестовый ключ")
	}
	c, out, stderr := localCommand(t)
	env := envFor(s.Dir)
	env["NOVAVPN_NODE_API_URL"] = "%"
	env["NOVAVPN_NODE_CA_FILE"] = filepath.Join(s.Dir, "absent")
	err := invoke(c, []string{"status"}, env, forbiddenReader{t})
	want := "server_id node-17\napplied.config_version 42\napplied.peers 3\napplied.applied_at 2026-10-21T10:40:00Z\ntoken_issued_at 2026-10-20T09:30:00Z\n"
	if err != nil || out.String() != want || stderr.Len() != 0 {
		t.Fatal("выведены неверные сохранённые метаданные")
	}
	noLeaks(t, out.String(), stderr.String(), err, ns.NodeToken, key.String())
	ns.Applied = state.Applied{}
	if err := s.Save(ns); err != nil {
		t.Fatal("не удалось сбросить метаданные")
	}
	out.Reset()
	if err := invoke(c, []string{"status"}, env, forbiddenReader{t}); err != nil {
		t.Fatal("нулевое время применения отвергнуто")
	}
	if !strings.Contains(out.String(), "applied.applied_at 0001-01-01T00:00:00Z\n") {
		t.Fatal("выдумано время применения")
	}
}

func TestStatusAndRunRejectMissingOrCorruptRegistration(t *testing.T) {
	value := secret(t)
	for _, name := range []string{"status", "run"} {
		for _, tc := range []struct{ name, raw, message string }{
			{"missing", "", "узел не инициализирован"}, {"empty", "{}", "узел не инициализирован"},
			{"no_token", `{"server_id":"node-17"}`, "узел не инициализирован"},
			{"no_server", `{"node_token":"` + value + `"}`, "узел не инициализирован"},
			{"corrupt", "{" + value, "чтение состояния"},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				if tc.raw != "" {
					if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(tc.raw), 0o600); err != nil {
						t.Fatal("не удалось записать тестовый файл")
					}
				}
				c, out, stderr := localCommand(t)
				env := envFor(dir)
				env["NOVAVPN_NODE_API_URL"] = "https://example.invalid"
				err := invoke(c, []string{name}, env, forbiddenReader{t})
				if err == nil || !strings.Contains(err.Error(), tc.message) || out.Len() != 0 {
					t.Fatal("неверная диагностика регистрации")
				}
				noLeaks(t, out.String(), stderr.String(), err, value)
			})
		}
	}
}

func tlsServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal("не удалось записать тестовый сертификат")
	}
	return srv, ca
}

func TestEnrollRealHTTPSRequestAndFreshState(t *testing.T) {
	s, previous := registeredStore(t)
	key, _ := s.PrivateKey()
	bootstrap, token := " \t"+secret(t)+" \t", secret(t)
	calls := 0
	srv, ca := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		raw, err := io.ReadAll(r.Body)
		var body map[string]string
		if err != nil || json.Unmarshal(raw, &body) != nil {
			t.Error("неверное тело регистрации")
		}
		if r.Method != "POST" || r.URL.Path != "/internal/v1/nodes/enroll" || r.Header.Get("Authorization") != "" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("неверный контракт запроса регистрации")
		}
		if len(body) != 2 || body["bootstrap_token"] != bootstrap || body["public_key"] != key.PublicKey().String() || bytes.Contains(raw, []byte(key.String())) {
			t.Error("неверные данные регистрации")
		}
		if r.TLS == nil || r.TLS.Version < tls.VersionTLS12 {
			t.Error("не соблюдена нижняя граница TLS")
		}
		_ = json.NewEncoder(w).Encode(api.NodeToken{ServerID: "node-new", NodeToken: token})
	})
	c, out, stderr := localCommand(t)
	env := envFor(s.Dir)
	env["NOVAVPN_NODE_API_URL"], env["NOVAVPN_NODE_CA_FILE"] = srv.URL, ca
	before := time.Now().UTC()
	err := invoke(c, []string{"enroll"}, env, strings.NewReader(bootstrap+"\r\n\r\n"))
	after := time.Now().UTC()
	ns, loadErr := s.Load()
	if err != nil || loadErr != nil || calls != 1 {
		t.Fatal("регистрация не завершилась")
	}
	if ns.ServerID != "node-new" || ns.NodeToken != token || ns.Applied != (state.Applied{}) || ns.TokenIssuedAt.Before(before) || ns.TokenIssuedAt.After(after) || ns.TokenIssuedAt.Location() != time.UTC {
		t.Fatal("сохранено неверное состояние регистрации")
	}
	info, statErr := os.Stat(filepath.Join(s.Dir, "state.json"))
	if statErr != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("неверные права регистрации")
	}
	noLeaks(t, out.String(), stderr.String(), err, bootstrap, token, previous.NodeToken, key.String())
}

func TestEnrollRejectsInputAndKeyBeforeHTTP(t *testing.T) {
	for _, kind := range []string{"empty", "whitespace", "read_error", "missing_key", "corrupt_key"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := registeredStore(t)
			before, _ := os.ReadFile(filepath.Join(s.Dir, "state.json"))
			value := secret(t)
			var input io.Reader = strings.NewReader(value)
			switch kind {
			case "empty":
				input = strings.NewReader("")
			case "whitespace":
				input = strings.NewReader(" \t\r\n")
			case "read_error":
				input = brokenIO{errors.New(value)}
			case "missing_key":
				if err := os.Remove(filepath.Join(s.Dir, "node.key")); err != nil {
					t.Fatal("не удалось убрать ключ")
				}
			case "corrupt_key":
				if err := os.WriteFile(filepath.Join(s.Dir, "node.key"), []byte(value), 0o600); err != nil {
					t.Fatal("не удалось повредить ключ")
				}
			}
			srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("отказ дошёл до HTTP") }))
			defer srv.Close()
			env := envFor(s.Dir)
			env["NOVAVPN_NODE_ENV"], env["NOVAVPN_NODE_ALLOW_INSECURE_API"], env["NOVAVPN_NODE_API_URL"] = "dev", "true", srv.URL
			c, out, stderr := localCommand(t)
			err := invoke(c, []string{"enroll"}, env, input)
			if err == nil || out.Len() != 0 {
				t.Fatal("неверный ввод принят")
			}
			after, _ := os.ReadFile(filepath.Join(s.Dir, "state.json"))
			if !bytes.Equal(before, after) {
				t.Fatal("отказ испортил прежнюю регистрацию")
			}
			if kind == "missing_key" {
				if _, err := os.Stat(filepath.Join(s.Dir, "node.key")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("регистрация сгенерировала новый ключ")
				}
			}
			noLeaks(t, out.String(), stderr.String(), err, value)
		})
	}
}

func TestEnrollFailedResponsesPreserveStateAndSecrets(t *testing.T) {
	for _, kind := range []string{"http_error", "bad_json", "no_server", "no_token", "whitespace_fields", "wrong_status"} {
		t.Run(kind, func(t *testing.T) {
			s, ns := registeredStore(t)
			key, _ := s.PrivateKey()
			bootstrap, token := secret(t), secret(t)
			before, _ := os.ReadFile(filepath.Join(s.Dir, "state.json"))
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				switch kind {
				case "http_error":
					w.WriteHeader(403)
					_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": bootstrap + ns.NodeToken + key.String()}})
				case "bad_json":
					_, _ = io.WriteString(w, "{"+bootstrap)
				case "no_server":
					_ = json.NewEncoder(w).Encode(api.NodeToken{NodeToken: token})
				case "no_token":
					_ = json.NewEncoder(w).Encode(api.NodeToken{ServerID: "node-new"})
				case "whitespace_fields":
					_ = json.NewEncoder(w).Encode(api.NodeToken{ServerID: " \t", NodeToken: "\n"})
				case "wrong_status":
					w.WriteHeader(201)
					_ = json.NewEncoder(w).Encode(api.NodeToken{ServerID: "node-new", NodeToken: token})
				}
			}))
			defer srv.Close()
			env := envFor(s.Dir)
			env["NOVAVPN_NODE_ENV"], env["NOVAVPN_NODE_ALLOW_INSECURE_API"], env["NOVAVPN_NODE_API_URL"] = "dev", "true", srv.URL
			c, out, stderr := localCommand(t)
			err := invoke(c, []string{"enroll"}, env, strings.NewReader(bootstrap))
			if err == nil || out.Len() != 0 || calls != 1 {
				t.Fatal("неверный ответ регистрации принят")
			}
			after, _ := os.ReadFile(filepath.Join(s.Dir, "state.json"))
			if !bytes.Equal(before, after) {
				t.Fatal("отказ изменил прежнюю регистрацию")
			}
			noLeaks(t, out.String(), stderr.String(), err, bootstrap, token, ns.NodeToken, key.String())
		})
	}
}

func TestNetworkConfigAndTrustFailures(t *testing.T) {
	for _, name := range []string{"enroll", "run"} {
		for _, kind := range []string{"missing_url", "bad_url", "bad_ca", "missing_ca", "untrusted", "legacy_ca", "http_prod", "http_dev_without_permission"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				s, ns := registeredStore(t)
				before, _ := os.ReadFile(filepath.Join(s.Dir, "state.json"))
				value := secret(t)
				srv, ca := tlsServer(t, func(http.ResponseWriter, *http.Request) {
					t.Error("неверная конфигурация дошла до HTTP")
				})
				env := envFor(s.Dir)
				env["NOVAVPN_NODE_API_URL"], env["NOVAVPN_NODE_CA_FILE"] = srv.URL, ca
				switch kind {
				case "missing_url":
					env["NOVAVPN_NODE_API_URL"] = ""
				case "bad_url":
					env["NOVAVPN_NODE_API_URL"] = "%" + value
				case "bad_ca":
					if err := os.WriteFile(ca, []byte(value), 0o600); err != nil {
						t.Fatal("не удалось повредить сертификат")
					}
				case "missing_ca":
					env["NOVAVPN_NODE_CA_FILE"] = filepath.Join(s.Dir, value)
				case "untrusted":
					env["NOVAVPN_NODE_CA_FILE"] = ""
				case "legacy_ca":
					env["NOVAVPN_NODE_CA_FILE"] = ""
					env["NOVAVPN_API_CA_FILE"] = ca
				case "http_prod":
					env["NOVAVPN_NODE_API_URL"] = "http://example.invalid/" + value
				case "http_dev_without_permission":
					env["NOVAVPN_NODE_API_URL"] = "http://example.invalid"
					env["NOVAVPN_NODE_ENV"] = "dev"
				}
				c, out, stderr := localCommand(t)
				if name == "run" && (kind == "untrusted" || kind == "legacy_ca") {
					c.openDevice = func() (nodeDevice, error) { return &testDevice{}, nil }
					c.runLoop = func(ctx context.Context, r *runtime.Runner) error {
						_, _, _, err := r.API.Desired(ctx, ns.ServerID, "")
						if err == nil {
							t.Error("недоверенный сертификат принят")
						}
						return err
					}
				}
				err := invoke(c, []string{name}, env, strings.NewReader(value))
				if err == nil || out.Len() != 0 {
					t.Fatal("неверная сетевая конфигурация принята")
				}
				if kind == "missing_url" && !strings.Contains(err.Error(), "NOVAVPN_NODE_API_URL") {
					t.Fatal("не указано имя отсутствующей настройки")
				}
				after, _ := os.ReadFile(filepath.Join(s.Dir, "state.json"))
				if !bytes.Equal(before, after) {
					t.Fatal("сетевой отказ изменил состояние")
				}
				noLeaks(t, out.String(), stderr.String(), err, value, ns.NodeToken)
			})
		}
	}
}

func TestEnrollSaveFailureIsNotSuccess(t *testing.T) {
	s, ns := registeredStore(t)
	bootstrap, token := secret(t), secret(t)
	path := filepath.Join(s.Dir, "state.json")
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if err := os.Rename(path, path+".previous"); err != nil {
			t.Error("не удалось сохранить тестовый файл")
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Error("не удалось создать препятствие записи")
		}
		_ = json.NewEncoder(w).Encode(api.NodeToken{ServerID: "node-new", NodeToken: token})
	}))
	defer srv.Close()
	env := envFor(s.Dir)
	env["NOVAVPN_NODE_ENV"], env["NOVAVPN_NODE_ALLOW_INSECURE_API"], env["NOVAVPN_NODE_API_URL"] = "dev", "true", srv.URL
	c, out, stderr := localCommand(t)
	err := invoke(c, []string{"enroll"}, env, strings.NewReader(bootstrap))
	if err == nil || !strings.Contains(err.Error(), "запись состояния") || out.Len() != 0 || calls != 1 {
		t.Fatal("ошибка записи выдана за успех")
	}
	noLeaks(t, out.String(), stderr.String(), err, bootstrap, token, ns.NodeToken)
}

type testDevice struct {
	closes   int
	closeErr error
}

func (d *testDevice) Close() error { d.closes++; return d.closeErr }
func (*testDevice) Snapshot(string) (wg.LiveState, error) {
	return wg.LiveState{}, errors.New("неожиданный снимок")
}
func (*testDevice) Configure(string, wgtypes.Config) error {
	return errors.New("неожиданная настройка")
}

func TestRunWiresRealComponentsAndClosesDevice(t *testing.T) {
	originalVersion := version
	version = "task9-test-build"
	t.Cleanup(func() { version = originalVersion })
	s, ns := registeredStore(t)
	calls := 0
	srv, ca := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/internal/v1/nodes/node-17/desired" || r.Header.Get("Authorization") != "Bearer "+ns.NodeToken {
			t.Error("сохранённый токен или путь не передан клиенту")
		}
		w.WriteHeader(http.StatusNotModified)
	})
	env := envFor(s.Dir)
	env["NOVAVPN_NODE_API_URL"], env["NOVAVPN_NODE_CA_FILE"] = srv.URL, ca
	env["NOVAVPN_NODE_INTERFACE"], env["NOVAVPN_NODE_POLL_INTERVAL"] = "wg9", "3s"
	c, out, stderr := localCommand(t)
	device := &testDevice{}
	opens, loops := 0, 0
	c.openDevice = func() (nodeDevice, error) { opens++; return device, nil }
	var received context.Context
	c.runLoop = func(ctx context.Context, r *runtime.Runner) error {
		loops++
		received = ctx
		if ctx == nil || ctx.Done() == nil || ctx.Err() != nil {
			t.Fatal("нет живого отменяемого контекста")
		}
		store, ok := r.Store.(*state.Store)
		if !ok || store.Dir != s.Dir {
			t.Fatal("не передан настоящий указатель хранилища")
		}
		applier, ok := r.Applier.(*wg.Applier)
		if !ok || applier.Device != device || applier.Iface != "wg9" {
			t.Fatal("неверная сборка применения")
		}
		if _, ok := applier.Link.(wg.Netlink); !ok {
			t.Fatal("не передан настоящий сетевой адаптер")
		}
		if _, ok := r.API.(*api.Client); !ok {
			t.Fatal("клиент API подменён")
		}
		if r.Iface != "wg9" || r.Interval != 3*time.Second || r.TokenTTL != 24*time.Hour || r.Version != version || r.Now == nil || r.Log == nil {
			t.Fatal("цикл собран не полностью")
		}
		before := time.Now()
		now := r.Now()
		after := time.Now()
		if now.Before(before) || now.After(after) {
			t.Fatal("не переданы настоящие часы")
		}
		_, _, unchanged, err := r.API.Desired(ctx, ns.ServerID, "")
		if err != nil || !unchanged {
			t.Fatal("собранный клиент не выполнил запрос")
		}
		r.Log.Info("проверка журнала")
		return nil
	}
	err := invoke(c, []string{"run"}, env, forbiddenReader{t})
	if err != nil || opens != 1 || loops != 1 || device.closes != 1 || calls != 1 || out.Len() != 0 {
		t.Fatal("неверный жизненный цикл команды")
	}
	if received.Err() != context.Canceled {
		t.Fatal("контекст сигнала не освобождён")
	}
	var entry map[string]any
	if json.Unmarshal(stderr.Bytes(), &entry) != nil || entry["msg"] != "проверка журнала" || entry["level"] != "INFO" {
		t.Fatal("журнал не записан в стандартную диагностику в формате JSON")
	}
	noLeaks(t, out.String(), stderr.String(), err, ns.NodeToken)
}

func TestRunRejectsKeyBeforeOpeningDevice(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt"} {
		t.Run(kind, func(t *testing.T) {
			s, ns := registeredStore(t)
			value := secret(t)
			path := filepath.Join(s.Dir, "node.key")
			if kind == "missing" {
				if err := os.Remove(path); err != nil {
					t.Fatal("не удалось убрать ключ")
				}
			} else if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
				t.Fatal("не удалось повредить ключ")
			}
			c, out, stderr := localCommand(t)
			env := envFor(s.Dir)
			env["NOVAVPN_NODE_API_URL"] = "https://example.invalid"
			err := invoke(c, []string{"run"}, env, forbiddenReader{t})
			if err == nil || !strings.Contains(err.Error(), "ключ") {
				t.Fatal("ошибка ключа не обнаружена до запуска")
			}
			noLeaks(t, out.String(), stderr.String(), err, ns.NodeToken, value)
		})
	}
}

func TestRunErrorsCancellationAndClose(t *testing.T) {
	for _, kind := range []string{"open", "loop", "close", "loop_and_close", "cancel", "cancel_and_close"} {
		t.Run(kind, func(t *testing.T) {
			s, ns := registeredStore(t)
			key, _ := s.PrivateKey()
			value := secret(t)
			sensitive := errors.New(value + ns.NodeToken + key.String())
			c, out, stderr := localCommand(t)
			device := &testDevice{}
			if strings.Contains(kind, "close") {
				device.closeErr = sensitive
			}
			c.openDevice = func() (nodeDevice, error) {
				if kind == "open" {
					return nil, sensitive
				}
				return device, nil
			}
			loops := 0
			c.runLoop = func(ctx context.Context, r *runtime.Runner) error {
				loops++
				if strings.HasPrefix(kind, "cancel") {
					return context.Canceled
				}
				if strings.HasPrefix(kind, "loop") {
					return sensitive
				}
				return nil
			}
			env := envFor(s.Dir)
			env["NOVAVPN_NODE_API_URL"] = "https://example.invalid"
			err := invoke(c, []string{"run"}, env, forbiddenReader{t})
			if (err == nil) != (kind == "cancel") {
				t.Fatal("неверный результат цикла или закрытия")
			}
			wantCalls := 1
			if kind == "open" {
				wantCalls = 0
			}
			if device.closes != wantCalls || loops != wantCalls {
				t.Fatal("нарушен порядок открытия, цикла и закрытия")
			}
			if strings.Contains(kind, "close") && !strings.Contains(err.Error(), "закрытие") {
				t.Fatal("ошибка закрытия потеряна")
			}
			noLeaks(t, out.String(), stderr.String(), err, value, ns.NodeToken, key.String())
		})
	}
}

func TestStdoutFailuresAreSafeErrors(t *testing.T) {
	for _, name := range []string{"--help", "init", "status"} {
		t.Run(name, func(t *testing.T) {
			s, ns := registeredStore(t)
			value := secret(t)
			c, _, stderr := localCommand(t)
			c.stdout = brokenIO{errors.New(value)}
			err := invoke(c, []string{name}, envFor(s.Dir), forbiddenReader{t})
			if err == nil {
				t.Fatal("ошибка вывода выдана за успех")
			}
			noLeaks(t, "", stderr.String(), err, value, ns.NodeToken)
		})
	}
}

func TestMainProcessHelper(t *testing.T) {
	if os.Getenv("NODE_TASK9_TEST_PROCESS") != "main" {
		return
	}
	os.Args = append([]string{os.Args[0]}, strings.Split(os.Getenv("NODE_TASK9_TEST_ARGS"), "\n")...)
	main()
}

func processCommand(t *testing.T, extra ...string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal("не удалось найти тестовый процесс")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestMainProcessHelper$")
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "NOVAVPN_") && !strings.HasPrefix(entry, "NODE_TASK9_TEST_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "NODE_TASK9_TEST_PROCESS=main")
	cmd.Env = append(cmd.Env, extra...)
	return cmd
}

func TestMainExitCodesAndSecretSafeStderr(t *testing.T) {
	value := secret(t)
	for _, arg := range []string{"--help", value} {
		cmd := processCommand(t, "NODE_TASK9_TEST_ARGS="+arg)
		var out, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &stderr
		err := cmd.Run()
		if arg == "--help" {
			if err != nil || !strings.Contains(out.String(), "status") || stderr.Len() != 0 {
				t.Fatal("процесс справки завершился неверно")
			}
		} else {
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(stderr.String(), "команд") {
				t.Fatal("неверный код или диагностика процесса")
			}
		}
		noLeaks(t, out.String(), stderr.String(), err, value)
	}
}

func TestSignalsStopRealCommandWithoutApplyingNetwork(t *testing.T) {
	for _, sig := range []os.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			s, ns := registeredStore(t)
			key, _ := s.PrivateKey()
			ready := make(chan struct{}, 1)
			srv, ca := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/internal/v1/nodes/node-17/desired" {
					select {
					case ready <- struct{}{}:
					default:
					}
				}
				w.WriteHeader(http.StatusServiceUnavailable)
			})
			cmd := processCommand(t, "NODE_TASK9_TEST_ARGS=run", "NOVAVPN_NODE_STATE_DIR="+s.Dir,
				"NOVAVPN_NODE_API_URL="+srv.URL, "NOVAVPN_NODE_CA_FILE="+ca)
			var out, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal("не удалось запустить дочерний процесс")
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case <-ready:
			case <-done:
				t.Fatal("процесс не дошёл до запроса желаемого набора")
			}
			if err := cmd.Process.Signal(sig); err != nil {
				_ = cmd.Process.Kill()
				<-done
				t.Fatal("не удалось доставить сигнал")
			}
			if err := <-done; err != nil {
				t.Fatal("сигнал не завершил процесс с кодом ноль")
			}
			noLeaks(t, out.String(), stderr.String(), nil, ns.NodeToken, key.String())
		})
	}
}
