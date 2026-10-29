package api

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustClient(t *testing.T, cfg Config) *Client {
	t.Helper()
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewValidatesConfig(t *testing.T) {
	bad := []struct {
		name string
		cfg  Config
	}{
		{"пустой адрес", Config{Env: "dev", AllowInsecure: true}},
		{"http вне dev", Config{BaseURL: "http://example.com", Env: "prod"}},
		{"пропуск проверки вне dev", Config{BaseURL: "https://example.com", Env: "prod", AllowInsecure: true}},
		{"пропуск проверки без окружения", Config{BaseURL: "https://example.com", AllowInsecure: true}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatal("недопустимая конфигурация принята")
			}
		})
	}
	if _, err := New(Config{BaseURL: "http://127.0.0.1:1", Env: "dev", AllowInsecure: true}); err != nil {
		t.Fatalf("dev-стенд по http отвергнут: %v", err)
	}
}

func TestNewDefaultsAndTrimsBaseURL(t *testing.T) {
	c, err := New(Config{BaseURL: "https://example.com/", Env: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if c.baseURL != "https://example.com" {
		t.Fatalf("базовый адрес %q; ожидался без завершающей косой черты", c.baseURL)
	}
	if c.hc.Timeout != 15*time.Second {
		t.Fatalf("таймаут %s; ожидалось 15s", c.hc.Timeout)
	}
	c, err = New(Config{BaseURL: "https://example.com", Env: "prod", Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if c.hc.Timeout != 3*time.Second {
		t.Fatalf("таймаут %s; ожидалось 3s", c.hc.Timeout)
	}
}

func TestNewRejectsCAFileWithoutCertificates(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, []byte("не сертификат"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{BaseURL: "https://example.com", Env: "prod", CAFile: ca}); err == nil {
		t.Fatal("файл CA без сертификатов принят")
	}
	if _, err := New(Config{BaseURL: "https://example.com", Env: "prod", CAFile: filepath.Join(dir, "нет.pem")}); err == nil {
		t.Fatal("отсутствующий файл CA принят")
	}
}

func TestDesiredDistinguishesNotModified(t *testing.T) {
	var gotETag, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotETag = r.Header.Get("If-None-Match")
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/internal/v1/nodes/s/desired" {
			t.Errorf("путь запроса %q", r.URL.Path)
		}
		w.Header().Set("ETag", `"abc"`)
		if gotETag == `"abc"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte(`{"server_id":"s","config_version":1,"mtu":1420,"listen_port":51820,` +
			`"tunnel_address":"10.99.0.1/24","dns_servers":["10.99.0.1"],"keepalive_sec":25,` +
			`"peers":[{"public_key":"k","allowed_ips":["10.99.0.2/32"],` +
			`"expires_at":"2026-11-27T10:00:00Z","state":"active"}],` +
			`"measured_at":"2026-10-27T10:00:00Z"}`))
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	c.SetToken("токен-узла")
	set, etag, notModified, err := c.Desired(context.Background(), "s", "")
	if err != nil || notModified || etag != `"abc"` || set.TunnelAddress != "10.99.0.1/24" {
		t.Fatalf("первый ответ: набор %+v, etag %q, notModified %v, ошибка %v", set, etag, notModified, err)
	}
	if gotETag != "" {
		t.Fatalf("первый запрос отправлен с If-None-Match %q", gotETag)
	}
	if gotAuth != "Bearer токен-узла" {
		t.Fatal("запрос отправлен без токена узла")
	}
	if set.ConfigVersion != 1 || set.MTU != 1420 || set.ListenPort != 51820 || set.KeepaliveSec != 25 {
		t.Fatalf("числовые поля набора: %+v", set)
	}
	if len(set.DNSServers) != 1 || set.DNSServers[0] != "10.99.0.1" {
		t.Fatalf("DNS-серверы %v", set.DNSServers)
	}
	if len(set.Peers) != 1 || set.Peers[0].State != "active" || set.Peers[0].PublicKey != "k" {
		t.Fatalf("пиры %+v", set.Peers)
	}
	if set.MeasuredAt.IsZero() || set.MeasuredAt.UTC().Format(time.RFC3339) != "2026-10-27T10:00:00Z" {
		t.Fatalf("measured_at %s", set.MeasuredAt)
	}
	_, etag, notModified, err = c.Desired(context.Background(), "s", `"abc"`)
	if err != nil || !notModified || etag != `"abc"` {
		t.Fatalf("второй ответ: etag %q, notModified %v, ошибка %v", etag, notModified, err)
	}
	if gotETag != `"abc"` {
		t.Fatalf("второй запрос отправлен с If-None-Match %q", gotETag)
	}
}

func TestDesiredRejectsBrokenJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"server_id":`))
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	if _, _, _, err := c.Desired(context.Background(), "s", ""); err == nil {
		t.Fatal("битый JSON принят за набор")
	}
}

func TestStatusErrorCarriesCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"unauthenticated","message":"нет"}}`))
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	_, _, _, err := c.Desired(context.Background(), "s", "")
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 401 || se.Code != "unauthenticated" {
		t.Fatalf("ошибка %v; ожидался StatusError 401 unauthenticated", err)
	}
}

func TestTLSVerificationAndCAFile(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"abc"`)
		_, _ = w.Write([]byte(`{"server_id":"s","config_version":1,"mtu":1420,"listen_port":51820,` +
			`"tunnel_address":"10.99.0.1/24","dns_servers":[],"keepalive_sec":25,"peers":[],` +
			`"measured_at":"2026-10-27T10:00:00Z"}`))
	}))
	defer srv.Close()
	if _, _, _, err := mustClient(t, Config{BaseURL: srv.URL, Env: "prod"}).Desired(context.Background(), "s", ""); err == nil {
		t.Fatal("самоподписанный сертификат принят без CA")
	}
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(ca, block, 0o600); err != nil {
		t.Fatal(err)
	}
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "prod", CAFile: ca})
	if _, _, _, err := c.Desired(context.Background(), "s", ""); err != nil {
		t.Fatalf("файл CA не применён: %v", err)
	}
}

func TestEnrollSendsNoToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/nodes/enroll" {
			t.Errorf("запрос %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("enroll отправлен с заголовком авторизации")
		}
		var in struct {
			BootstrapToken string `json:"bootstrap_token"`
			PublicKey      string `json:"public_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("тело enroll не разобрано: %v", err)
		}
		if in.BootstrapToken != "стартовый" || in.PublicKey != "ключ" {
			t.Errorf("тело enroll: стартовый токен %q, ключ %q", in.BootstrapToken, in.PublicKey)
		}
		_, _ = w.Write([]byte(`{"server_id":"srv","node_token":"новый-токен"}`))
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	c.SetToken("прежний-токен")
	nt, err := c.Enroll(context.Background(), "стартовый", "ключ")
	if err != nil {
		t.Fatal(err)
	}
	if nt.ServerID != "srv" || nt.NodeToken != "новый-токен" {
		t.Fatalf("ответ enroll: сервер %q", nt.ServerID)
	}
}

func TestReportExpects204(t *testing.T) {
	status := http.StatusNoContent
	var seen []string
	var hb map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer токен-узла" {
			t.Error("отчёт отправлен без токена узла")
		}
		if r.URL.Path == "/internal/v1/nodes/srv/heartbeat" {
			if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
				t.Errorf("тело heartbeat не разобрано: %v", err)
			}
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	c.SetToken("токен-узла")
	rep := ObservedReport{
		ConfigVersion: 3,
		Peers:         []ObservedPeer{{PublicKey: "k", RxBytes: 1, TxBytes: 2}},
	}
	if err := c.Observed(context.Background(), "srv", rep); err != nil {
		t.Fatalf("отчёт отклонён: %v", err)
	}
	if len(seen) != 1 || seen[0] != "POST /internal/v1/nodes/srv/observed" {
		t.Fatalf("запросы %v", seen)
	}
	load := 0.5
	if err := c.Heartbeat(context.Background(), "srv", Heartbeat{
		AgentVersion: "1.0", AgentUptimeSec: 60, Load1: &load, AppliedConfigVersion: 3,
	}); err != nil {
		t.Fatalf("heartbeat отклонён: %v", err)
	}
	if len(seen) != 2 || seen[1] != "POST /internal/v1/nodes/srv/heartbeat" {
		t.Fatalf("запросы %v", seen)
	}
	if _, ok := hb["cpu_pct"]; !ok || hb["cpu_pct"] != nil {
		t.Fatalf("cpu_pct %v; ожидался ключ со значением null", hb["cpu_pct"])
	}
	if hb["load1"] != 0.5 {
		t.Fatalf("load1 %v; ожидалось 0.5", hb["load1"])
	}
	status = http.StatusOK
	err := c.Observed(context.Background(), "srv", rep)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 200 {
		t.Fatalf("ответ 200 принят за успешный отчёт: %v", err)
	}
}

func TestRotateTokenSendsCurrentToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/nodes/srv/token/rotate" {
			t.Errorf("запрос %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"server_id":"srv","node_token":"следующий"}`))
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	c.SetToken("текущий")
	if _, err := c.RotateToken(context.Background(), "srv"); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer текущий" {
		t.Fatal("ротация отправлена не с текущим токеном")
	}
}

func TestResponseBodyLimit(t *testing.T) {
	big := strings.Repeat("а", 1<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"abc"`)
		_, _ = w.Write([]byte(`{"server_id":"` + big + `"}`))
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	if _, _, _, err := c.Desired(context.Background(), "s", ""); err == nil {
		t.Fatal("тело больше 1 МиБ принято")
	}
}
