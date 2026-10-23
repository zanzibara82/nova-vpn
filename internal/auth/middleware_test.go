package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/httpx"
)

type stubDenylist struct {
	denied map[string]bool
	err    error
	seen   []string
}

func (s *stubDenylist) Add(_ context.Context, jti string, _ time.Time) error {
	s.seen = append(s.seen, jti)
	return s.err
}

func (s *stubDenylist) Contains(_ context.Context, jti string) (bool, error) {
	return s.denied[jti], s.err
}

// newProtectedHandler — middleware поверх обработчика, который проверяет, что субъект
// действительно лёг в контекст. httpx импортируется напрямую: обёртка тут не нужна.
func newProtectedHandler(t *testing.T, deny Denylist) (http.Handler, *Issuer, uuid.UUID) {
	t.Helper()
	iss := NewIssuer(bytes32("unit-middleware-secret-0000"), time.Minute)
	user := uuid.New()
	sess := &SessionService{iss: iss, deny: deny, refreshTTL: time.Hour, log: slog.New(slog.DiscardHandler)}
	wrapped := Middleware(sess, deny)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := httpx.UserIDFromContext(r.Context())
		if !ok || got != user {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	return wrapped, iss, user
}

func TestMiddlewareAcceptsValidToken(t *testing.T) {
	h, iss, user := newProtectedHandler(t, &stubDenylist{denied: map[string]bool{}})
	tok, err := iss.Issue(context.Background(), user)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Value)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", w.Code, w.Body)
	}
}

func TestMiddlewareRejects(t *testing.T) {
	cases := map[string]func(*http.Request){
		"no header":    func(*http.Request) {},
		"wrong scheme": func(r *http.Request) { r.Header.Set("Authorization", "Basic dXNlcjpwYXNz") },
		"empty bearer": func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") },
		"junk token":   func(r *http.Request) { r.Header.Set("Authorization", "Bearer abc.def.ghi") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h, _, _ := newProtectedHandler(t, &stubDenylist{denied: map[string]bool{}})
			req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
			mutate(req)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			assertUnauthenticated(t, w)
		})
	}
}

func assertUnauthenticated(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	var body struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("envelope is not JSON: %s", w.Body)
	}
	if body.Error.Code != "unauthenticated" {
		t.Errorf("code = %q, want unauthenticated", body.Error.Code)
	}
	if len(body.Error.RequestID) != 16 {
		t.Errorf("request_id = %q, want 16 chars", body.Error.RequestID)
	}
}

func TestMiddlewareRejectsDeniedJTI(t *testing.T) {
	deny := &stubDenylist{denied: map[string]bool{}}
	h, iss, user := newProtectedHandler(t, deny)
	tok, err := iss.Issue(context.Background(), user)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	deny.denied[tok.JTI] = true
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Value)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assertUnauthenticated(t, w)
}

func TestMiddlewareFailsOpenWhenDenylistIsDown(t *testing.T) {
	deny := &stubDenylist{err: errors.New("redis: connection refused")}
	h, iss, user := newProtectedHandler(t, deny)
	tok, err := iss.Issue(context.Background(), user)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Value)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (fail-open)", w.Code)
	}
}
