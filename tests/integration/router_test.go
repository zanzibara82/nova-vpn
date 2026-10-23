//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/novavpn/novavpn/internal/config"
	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/entitlements"
	"github.com/novavpn/novavpn/services/api"
)

// isolatedRedis — чистый Redis для тестов сборки: бакеты лимитеров и denylist
// не переходят между тестами.
func isolatedRedis(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("NOVAVPN_REDIS_ADDR")
	if addr == "" {
		t.Skip("NOVAVPN_REDIS_ADDR is not set; run `make up-dev` first")
	}
	c := redis.NewClient(&redis.Options{Addr: addr, DB: 9})
	ctx := context.Background()
	if err := c.Ping(ctx).Err(); err != nil {
		t.Fatalf("redis db 9 at %s: %v", addr, err)
	}
	// FlushDB бьёт только по девятой базе: её использует исключительно этот файл.
	if err := c.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flush db 9: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func newRouter(t *testing.T) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	h := api.NewRouter(api.Deps{
		Cfg: config.Config{
			Env:        config.EnvDev,
			JWTSecret:  bytes32ForTests(),
			AccessTTL:  10 * time.Minute,
			RefreshTTL: 24 * time.Hour,
		},
		Pool: pool(t),
		RDB:  isolatedRedis(t),
		Ent:  entitlements.New(db.New(pool(t))),
		Log:  slog.New(slog.NewJSONHandler(&buf, nil)),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, &buf
}

func TestRouterServesDocumentedRoutes(t *testing.T) {
	srv, _ := newRouter(t)
	base := srv.URL

	// Несуществующий путь — тот же конверт, что и все остальные ошибки (§5.2).
	resp, body := do(t, http.MethodGet, base+"/api/v1/nothing-here", nil, "")
	if resp.StatusCode != http.StatusNotFound || errorCode(t, body) != "not_found" {
		t.Fatalf("unknown path = %d %v, want 404 not_found", resp.StatusCode, body)
	}

	// Закрытый маршрут без токена — 401, и это НЕ 404: маршрут существует и
	// смонтирован. Именно так тест отличает «забыли подключить devices» от
	// «подключили, но требовательно».
	resp, body = do(t, http.MethodGet, base+"/api/v1/devices", nil, "")
	if resp.StatusCode != http.StatusUnauthorized || errorCode(t, body) != "unauthenticated" {
		t.Fatalf("devices without token = %d %v", resp.StatusCode, body)
	}

	// Health живёт вне /api/v1 и не требует аутентификации. Тело — plain text,
	// поэтому без do: та разбирает ответ как JSON.
	hresp, err := http.Get(base + "/debug/health")
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK {
		t.Fatalf("health = %d, want 200", hresp.StatusCode)
	}
	// Сквозной путь (register → me → devices) здесь не повторяется: он
	// в auth_flow_test.go. Здесь проверяется именно сборка, а не правила.
}

func TestRouterRejectsMethodWithEnvelope(t *testing.T) {
	srv, _ := newRouter(t)
	// ServeMux на PUT к login ответил бы текстом без request_id; «единый формат
	// ошибки» соблюдается только если сборщик дописывает конверт сам.
	resp, body := do(t, http.MethodPut, srv.URL+"/api/v1/auth/login", nil, "")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d %v, want 405", resp.StatusCode, body)
	}
	if errorCode(t, body) != "method_not_allowed" {
		t.Errorf("body = %v, want code method_not_allowed", body)
	}
	if allow := resp.Header.Get("Allow"); !strings.Contains(allow, "POST") {
		t.Errorf("Allow = %q, must list POST", allow)
	}
}

func TestRouterJournalHasNoSecrets(t *testing.T) {
	srv, buf := newRouter(t)
	base := srv.URL
	email := "journal-" + uuid.NewString()[:8] + "@novavpn.test"

	resp, body := do(t, http.MethodPost, base+"/api/v1/auth/register",
		map[string]string{"email": email, "password": testPassword}, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register = %d %v", resp.StatusCode, body)
	}
	sess := decodeSession(t, body)

	lower := strings.ToLower(buf.String())
	if strings.Contains(lower, strings.ToLower(testPassword)) {
		t.Error("journal contains the password")
	}
	if strings.Contains(lower, strings.ToLower(sess.AccessToken)) ||
		strings.Contains(lower, strings.ToLower(sess.RefreshToken)) {
		t.Error("journal contains a token")
	}
	if strings.Contains(lower, "authorization") {
		t.Error("journal mentions the Authorization header")
	}
	if !strings.Contains(buf.String(), `"route":"POST /api/v1/auth/register"`) {
		t.Errorf("journal must carry the matched route, got %s", buf.String())
	}

	// /me — здесь появляется user id: без него матрицу «роль × маршрут» из задачи 19
	// нечем проверять, кроме статуса.
	buf.Reset()
	resp, body = do(t, http.MethodGet, base+"/api/v1/me", nil, sess.AccessToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me = %d %v", resp.StatusCode, body)
	}
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry); err != nil {
		t.Fatalf("journal line: %v (%s)", err, buf.String())
	}
	if entry["route"] != "GET /api/v1/me" {
		t.Errorf("route = %v", entry["route"])
	}
	if uid, _ := entry["user_id"].(string); len(uid) != 36 {
		t.Errorf("user_id = %q, want uuid of the authenticated user", uid)
	}
	if id, _ := entry["request_id"].(string); len(id) != 16 {
		t.Errorf("request_id = %q, want 16 hex chars", id)
	}
}

func TestRouterRateLimitsAnonymousRoutes(t *testing.T) {
	srv, _ := newRouter(t)
	base := srv.URL

	// Анонимный register обязан упереться в bucket по IP: burst = 5, так что 429
	// приходит не позже шестого запроса. Email каждый раз новый — значит 409
	// исключён, и 429 нельзя объяснить конфликтом.
	var codes []int
	for i := 0; i < 40; i++ {
		resp, _ := do(t, http.MethodPost, base+"/api/v1/auth/register",
			map[string]string{"email": "rl-" + uuid.NewString()[:8] + "@novavpn.test",
				"password": testPassword}, "")
		codes = append(codes, resp.StatusCode)
		if resp.StatusCode == http.StatusTooManyRequests {
			break
		}
	}
	limited := false
	for i, c := range codes {
		if c == http.StatusTooManyRequests {
			limited = true
			break
		}
		if c != http.StatusCreated {
			t.Fatalf("attempt %d = %d, want 201 before the limit, all=%v", i, c, codes)
		}
	}
	if !limited {
		t.Fatalf("anonymous register must hit the per-IP bucket, got %v", codes)
	}
}
