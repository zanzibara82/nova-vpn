//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/entitlements"
	"github.com/novavpn/novavpn/internal/httpx"
)

const testPassword = "integration-password-1"

func discardLog() *slog.Logger { return slog.New(slog.DiscardHandler) }

// newAuthServer собирает ровно тот граф, который соберёт задача 18: единый ServeMux,
// публичные маршруты под dec.Anonymous, приватные — под dec.Auth. В этом тесте обе
// обёртки сквозные, кроме Auth: без проверки access JWT тест не мог бы отличить 401
// от «забыли обёртку».
func newAuthServer(t *testing.T) (*httptest.Server, *db.Queries) {
	t.Helper()
	p := pool(t)
	q := db.New(p)
	iss := auth.NewIssuer(bytes32ForTests(), 10*time.Minute)
	deny := auth.NewRedisDenylist(redisClient(t), discardLog())
	sess := auth.NewSessionService(q, iss, deny, 24*time.Hour, discardLog())
	guard := auth.NewLoginGuard(redisClient(t), discardLog())
	h := auth.NewHandler(sess, p, entitlements.New(q), guard, "internal-default", discardLog())

	passthrough := func(next http.Handler) http.Handler { return next }
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, httpx.Decorators{
		Auth:      auth.Middleware(sess, deny),
		Anonymous: passthrough,
	})
	srv := httptest.NewServer(httpx.NewRequestID(mux))
	t.Cleanup(srv.Close)
	return srv, q
}

type sessionResp struct {
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token"`
	TokenType        string    `json:"token_type"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

func decodeSession(t *testing.T, body map[string]any) sessionResp {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	var s sessionResp
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("session shape: %v", err)
	}
	if s.AccessToken == "" || s.RefreshToken == "" {
		t.Fatalf("empty session: %+v", s)
	}
	return s
}

func jsonBody(v any) io.Reader {
	raw, _ := json.Marshal(v)
	return bytes.NewReader(raw)
}

func do(t *testing.T, method, url string, body any, bearer string) (*http.Response, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = jsonBody(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(data) > 0 {
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatalf("body %q is not JSON", data)
		}
	}
	return resp, out
}

// 16 hex символов — формат request_id из httpx.newRequestID.
func isHex16(s string) bool {
	if len(s) != 16 {
		return false
	}
	return strings.Trim(s, "0123456789abcdef") == ""
}

func errorCode(t *testing.T, body map[string]any) string {
	t.Helper()
	e, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("response has no error envelope: %v", body)
	}
	if id, ok := e["request_id"].(string); !ok || !isHex16(id) {
		t.Errorf("error envelope request_id %v must be 16 hex chars", e["request_id"])
	}
	code, _ := e["code"].(string)
	return code
}

// envelopePair — «code|message» из конверта без request_id. Нужен ровно для одного:
// сравнить два отказа как «одинаковый ответ», не сравнив при этом случайное.
func envelopePair(body map[string]any) string {
	e, _ := body["error"].(map[string]any)
	return fmt.Sprint(e["code"], "|", e["message"])
}

func TestRegisterThenRotateThenLogoutDeniesAccess(t *testing.T) {
	srv, q := newAuthServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	base := srv.URL + "/api/v1"

	email := "flow-" + uuid.NewString()[:8] + "@novavpn.test"
	resp, body := do(t, http.MethodPost, base+"/auth/register",
		map[string]string{"email": email, "password": testPassword}, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %v", resp.StatusCode, body)
	}
	sess := decodeSession(t, body)
	if sess.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", sess.TokenType)
	}
	// Access обязан истекать раньше refresh, иначе TTL 10 минут нигде не проверяется.
	if !sess.AccessExpiresAt.Before(sess.RefreshExpiresAt) {
		t.Errorf("access_expires_at %v not before refresh_expires_at %v",
			sess.AccessExpiresAt, sess.RefreshExpiresAt)
	}

	resp, body = do(t, http.MethodGet, base+"/me", nil, sess.AccessToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me: %d %v", resp.StatusCode, body)
	}
	user := body["user"].(map[string]any)
	if user["email"] != email || user["status"] != "active" {
		t.Errorf("me.user = %v", user)
	}
	plan := body["plan"].(map[string]any)
	if plan["slug"] != "internal-default" || plan["device_limit"].(float64) != 3 {
		t.Errorf("plan after register = %v", plan)
	}
	// Внутренний план без квоты: null, а не 0 (спецификация §13.4, ТЗ §19.3).
	if q, ok := plan["traffic_quota_bytes"]; !ok || q != nil {
		t.Errorf("internal-default is unlimited: traffic_quota_bytes = %v (ok=%v), want null", q, ok)
	}
	usage := body["devices"].(map[string]any)
	if usage["live"].(float64) != 0 || usage["limit"].(float64) != 3 {
		t.Errorf("devices usage = %v, want live=0 limit=3", usage)
	}

	resp, body = do(t, http.MethodPost, base+"/auth/refresh",
		map[string]string{"refresh_token": sess.RefreshToken}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %d %v", resp.StatusCode, body)
	}
	rotated := decodeSession(t, body)
	if rotated.RefreshToken == sess.RefreshToken || rotated.AccessToken == sess.AccessToken {
		t.Error("refresh returned the same pair")
	}

	// Старый refresh = предъявление не текущего секрета живущей семьи → гасится вся семья.
	resp, body = do(t, http.MethodPost, base+"/auth/refresh",
		map[string]string{"refresh_token": sess.RefreshToken}, "")
	if resp.StatusCode != http.StatusUnauthorized || errorCode(t, body) != "refresh_token_invalid" {
		t.Fatalf("reuse of old refresh: %d %v", resp.StatusCode, body)
	}
	resp, _ = do(t, http.MethodPost, base+"/auth/refresh",
		map[string]string{"refresh_token": rotated.RefreshToken}, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Error("family survived reuse detection")
	}

	// Отдельная сессия через login: logout обязан отозвать её, а не семью из теста выше.
	resp, body = do(t, http.MethodPost, base+"/auth/login",
		map[string]string{"email": email, "password": testPassword}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: %d %v", resp.StatusCode, body)
	}
	re := decodeSession(t, body)
	req, err := http.NewRequest(http.MethodPost, base+"/auth/logout",
		jsonBody(map[string]string{"refresh_token": re.RefreshToken}))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+re.AccessToken)
	lr, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	lr.Body.Close()
	if lr.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status = %d, want 204", lr.StatusCode)
	}
	if resp, body := do(t, http.MethodGet, base+"/me", nil, re.AccessToken); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked access token still authorized: %d %v", resp.StatusCode, body)
	}
	// Пользователь остаётся: отзыв сессии ≠ удаление учётной записи (ТЗ §11 делает это
	// отдельной операцией, цикл D).
	if _, err := q.UserByEmail(ctx, email); err != nil {
		t.Fatalf("user vanished after logout: %v", err)
	}
}

func TestAuthRejectedPaths(t *testing.T) {
	srv, q := newAuthServer(t)
	ctx := context.Background()
	base := srv.URL + "/api/v1"
	email := "reject-" + uuid.NewString()[:8] + "@novavpn.test"

	resp, body := do(t, http.MethodPost, base+"/auth/register",
		map[string]string{"email": email, "password": "short"}, "")
	if resp.StatusCode != http.StatusBadRequest || errorCode(t, body) != "invalid_request" {
		t.Fatalf("weak password: %d %v", resp.StatusCode, body)
	}
	if _, err := q.UserByEmail(ctx, email); err == nil {
		t.Error("user created despite rejected password")
	}

	if resp, body := do(t, http.MethodPost, base+"/auth/register",
		map[string]string{"email": email, "password": testPassword}, ""); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %v", resp.StatusCode, body)
	}
	// citext: регистр в email не различается, и повтор обязан быть 409, а не вторым аккаунтом.
	resp, body = do(t, http.MethodPost, base+"/auth/register",
		map[string]string{"email": strings.ToUpper(email), "password": testPassword}, "")
	if resp.StatusCode != http.StatusConflict || errorCode(t, body) != "email_taken" {
		t.Fatalf("duplicate email: %d %v", resp.StatusCode, body)
	}

	_, badPass := do(t, http.MethodPost, base+"/auth/login",
		map[string]string{"email": email, "password": "wrong-password-123"}, "")
	_, unknown := do(t, http.MethodPost, base+"/auth/login",
		map[string]string{"email": "nobody-" + uuid.NewString()[:8] + "@novavpn.test",
			"password": testPassword}, "")
	// Разница в message или details выдаёт, что email существует.
	// Сравнивается пара «code|message», а не whole map: request_id различается по
	// определению, и сравнение карт целиком было бы всегда красным.
	if envelopePair(badPass) != envelopePair(unknown) {
		t.Errorf("login answers differ: %v vs %v", badPass, unknown)
	}
	if errorCode(t, badPass) != "invalid_credentials" {
		t.Errorf("code = %v, want invalid_credentials", badPass)
	}

	user := userIDByEmail(t, ctx, q, email)
	// Форма «указатель на строку» — как у всех nullable-параметров этого плана при
	// emit_pointers_for_null_types: true (ср. DisplayName в InsertUserParams). Если
	// sqlc сгенерировал скаляр, правь эту строку, строку в тесте блокировки ниже и
	// вызов в задаче 19 одним коммитом: две формы в одном пакете не компилируются.
	lockedReason := "manual review"
	if err := q.LockUser(ctx, db.LockUserParams{ID: user, LockedReason: &lockedReason}); err != nil {
		t.Fatalf("LockUser: %v", err)
	}
	resp, body = do(t, http.MethodPost, base+"/auth/login",
		map[string]string{"email": email, "password": testPassword}, "")
	if resp.StatusCode != http.StatusForbidden || errorCode(t, body) != "account_locked" {
		t.Fatalf("locked account: %d %v", resp.StatusCode, body)
	}

	resp, body = do(t, http.MethodGet, base+"/me", nil, "")
	if resp.StatusCode != http.StatusUnauthorized || errorCode(t, body) != "unauthenticated" {
		t.Fatalf("me without token: %d %v", resp.StatusCode, body)
	}
}

func userIDByEmail(t *testing.T, ctx context.Context, q *db.Queries, email string) uuid.UUID {
	t.Helper()
	u, err := q.UserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("UserByEmail(%s): %v", email, err)
	}
	return u.ID
}

func TestLockedAccountCannotRefresh(t *testing.T) {
	srv, q := newAuthServer(t)
	ctx := context.Background()
	base := srv.URL + "/api/v1"
	email := "lockref-" + uuid.NewString()[:8] + "@novavpn.test"

	resp, body := do(t, http.MethodPost, base+"/auth/register",
		map[string]string{"email": email, "password": testPassword}, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %v", resp.StatusCode, body)
	}
	first := decodeSession(t, body)

	// До блокировки ротация обязана работать — иначе тест проверял бы не блокировку.
	resp, body = do(t, http.MethodPost, base+"/auth/refresh",
		map[string]string{"refresh_token": first.RefreshToken}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh before lock: %d %v", resp.StatusCode, body)
	}
	rotated := decodeSession(t, body)

	locked := "manual review"
	if err := q.LockUser(ctx, db.LockUserParams{
		ID: userIDByEmail(t, ctx, q, email), LockedReason: &locked,
	}); err != nil {
		t.Fatalf("LockUser: %v", err)
	}
	resp, body = do(t, http.MethodPost, base+"/auth/refresh",
		map[string]string{"refresh_token": rotated.RefreshToken}, "")
	if resp.StatusCode != http.StatusForbidden || errorCode(t, body) != "account_locked" {
		t.Fatalf("refresh on locked account: %d %v", resp.StatusCode, body)
	}
	// Блокировка ≠ удаление и ≠ отзыв семей: админский отзыв
	// (db.RevokeAllFamiliesForUser) — маршрут /api/v1/admin/* из A-2. Здесь важно,
	// что учётная запись цела и её можно разблокировать.
	if _, err := q.UserByEmail(ctx, email); err != nil {
		t.Fatalf("user vanished after lock: %v", err)
	}
}
