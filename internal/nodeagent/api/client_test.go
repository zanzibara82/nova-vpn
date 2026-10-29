package api

import (
	"context"
	"crypto/tls"
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
		{"адрес без хоста", Config{BaseURL: "https:///x", Env: "prod"}},
		{"неподдерживаемая схема", Config{BaseURL: "ftp://example.com", Env: "prod"}},
		{"http в dev без пропуска проверки", Config{BaseURL: "http://127.0.0.1:1", Env: "dev"}},
		{"параметры в адресе", Config{BaseURL: "https://example.com/?a=1", Env: "prod"}},
		{"пустой запрос в адресе", Config{BaseURL: "https://example.com?", Env: "prod"}},
		{"фрагмент в адресе", Config{BaseURL: "https://example.com/#f", Env: "prod"}},
		{"учётные данные в адресе", Config{BaseURL: "https://user:pass@example.com", Env: "prod"}},
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
	tr, ok := c.hc.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("минимальная версия TLS не 1.2")
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

func TestDesiredRequiresOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"abc"`)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	_, _, _, err := c.Desired(context.Background(), "s", "")
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusNoContent {
		t.Fatalf("204 принят за пустой набор: %v", err)
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
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type enroll %q", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("Accept enroll %q", r.Header.Get("Accept"))
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
	var hb, obs map[string]any
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
		if r.URL.Path == "/internal/v1/nodes/srv/observed" {
			if err := json.NewDecoder(r.Body).Decode(&obs); err != nil {
				t.Errorf("тело observed не разобрано: %v", err)
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
	peers, ok := obs["peers"].([]any)
	if !ok || len(peers) != 1 {
		t.Fatalf("пиры observed %v; ожидался массив из одного элемента", obs["peers"])
	}
	peer, ok := peers[0].(map[string]any)
	if !ok {
		t.Fatalf("пиер observed %v", peers[0])
	}
	if hs, exists := peer["latest_handshake"]; !exists || hs != nil {
		t.Fatalf("latest_handshake %v; ожидался ключ со значением null", hs)
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
	err := c.Heartbeat(context.Background(), "srv", Heartbeat{
		AgentVersion: "1.0", AgentUptimeSec: 60, Load1: &load, AppliedConfigVersion: 3,
	})
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 200 {
		t.Fatalf("ответ 200 принят за успешный heartbeat: %v", err)
	}
	if err.Error() != "api: отказ 200" {
		t.Fatalf("текст ошибки %q; ожидался %q", err.Error(), "api: отказ 200")
	}
	err = c.Observed(context.Background(), "srv", rep)
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
	nt, err := c.RotateToken(context.Background(), "srv")
	if err != nil {
		t.Fatal(err)
	}
	if nt.ServerID != "srv" || nt.NodeToken != "следующий" {
		t.Fatalf("ответ ротации: сервер %q, токен %q", nt.ServerID, nt.NodeToken)
	}
	if gotAuth != "Bearer текущий" {
		t.Fatal("ротация отправлена не с текущим токеном")
	}
}

func TestResponseBodyLimit(t *testing.T) {
	big := strings.Repeat("а", 1<<20)
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"abc"`)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"server_id":"` + big + `"}`))
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	if _, _, _, err := c.Desired(context.Background(), "s", ""); err == nil {
		t.Fatal("тело больше 1 МиБ принято")
	}
	status = http.StatusUnauthorized
	_, _, _, err := c.Desired(context.Background(), "s", "")
	if err == nil || !strings.Contains(err.Error(), "больше") {
		t.Fatalf("ошибка ошибочного ответа %v; ожидалось превышение предела", err)
	}
	var se *StatusError
	if errors.As(err, &se) {
		t.Fatalf("предел тела подменён StatusError: %v", err)
	}
}

func TestDesiredEscapesServerID(t *testing.T) {
	var escaped string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escaped = r.URL.EscapedPath()
		w.Header().Set("ETag", `"abc"`)
		_, _ = w.Write([]byte(`{"server_id":"a/b","config_version":1,"mtu":1420,"listen_port":51820,` +
			`"tunnel_address":"10.99.0.1/24","dns_servers":[],"keepalive_sec":25,"peers":[],` +
			`"measured_at":"2026-10-27T10:00:00Z"}`))
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	if _, _, _, err := c.Desired(context.Background(), "a/b", ""); err != nil {
		t.Fatal(err)
	}
	if escaped != "/internal/v1/nodes/a%2Fb/desired" {
		t.Fatalf("путь запроса %q; идентификатор сервера не закодирован", escaped)
	}
}

func TestRedirectRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/other", http.StatusFound)
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	_, _, _, err := c.Desired(context.Background(), "s", "")
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusFound {
		t.Fatalf("перенаправление не отвергнуто: %v", err)
	}
}

func TestTokenEndpointsRequireOK(t *testing.T) {
	status := http.StatusNoContent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	defer srv.Close()
	c := mustClient(t, Config{BaseURL: srv.URL, Env: "dev", AllowInsecure: true})
	c.SetToken("текущий")
	var se *StatusError
	if _, err := c.Enroll(context.Background(), "стартовый", "ключ"); !errors.As(err, &se) || se.Status != http.StatusNoContent {
		t.Fatalf("enroll принял 204: %v", err)
	}
	if _, err := c.RotateToken(context.Background(), "srv"); !errors.As(err, &se) || se.Status != http.StatusNoContent {
		t.Fatalf("ротация приняла 204: %v", err)
	}
	status = http.StatusNotModified
	if _, err := c.Enroll(context.Background(), "стартовый", "ключ"); !errors.As(err, &se) || se.Status != http.StatusNotModified {
		t.Fatalf("enroll принял 304: %v", err)
	}
	if _, err := c.RotateToken(context.Background(), "srv"); !errors.As(err, &se) || se.Status != http.StatusNotModified {
		t.Fatalf("ротация приняла 304: %v", err)
	}
}
