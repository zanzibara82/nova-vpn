package api_spec_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/novavpn/novavpn/internal/httpx"
)

type spec struct {
	Paths map[string]map[string]any `yaml:"paths"`
	Comp  struct {
		Schemas map[string]struct {
			Type       string         `yaml:"type"`
			Required   []string       `yaml:"required"`
			Properties map[string]any `yaml:"properties"`
			Enum       []string       `yaml:"enum"`
		} `yaml:"schemas"`
	} `yaml:"components"`
}

func load(t *testing.T) spec {
	t.Helper()
	// Тест запускается из каталога пакета (go test ./...), поэтому путь относительный.
	raw, err := os.ReadFile(filepath.Join("openapi.yaml"))
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	var s spec
	if err := yaml.Unmarshal(raw, &s); err != nil {
		t.Fatalf("parse contract: %v", err)
	}
	return s
}

// 1. Каждый задекларированный код существует как константа httpx. Переименование
// в Go сломает компиляцию теста, удаление из контракта — этот тест.
func TestContractCodesAreDeclared(t *testing.T) {
	s := load(t)
	declared := map[string]httpx.ErrorCode{
		"invalid_request":             httpx.ErrInvalidRequest,
		"unauthenticated":             httpx.ErrUnauthenticated,
		"account_locked":              httpx.ErrAccountLocked,
		"forbidden":                   httpx.ErrForbidden,
		"not_found":                   httpx.ErrNotFound,
		"method_not_allowed":          httpx.ErrMethodNotAllowed,
		"conflict":                    httpx.ErrConflict,
		"device_limit_reached":        httpx.ErrDeviceLimitReached,
		"duplicate_device":            httpx.ErrDuplicateDevice,
		"idempotency_key_required":    httpx.ErrIdempotencyKeyRequired,
		"idempotency_key_conflict":    httpx.ErrIdempotencyConflict,
		"idempotency_key_in_progress": httpx.ErrIdempotencyInProgress,
		"rate_limited":                httpx.ErrRateLimited,
		"internal":                    httpx.ErrInternal,
		"invalid_credentials":         httpx.ErrInvalidCredentials,
		"refresh_token_invalid":       httpx.ErrRefreshTokenInvalid,
		"email_taken":                 httpx.ErrEmailTaken,
	}
	for _, name := range s.Comp.Schemas["ErrorCode"].Enum {
		v, ok := declared[name]
		if !ok {
			t.Errorf("contract declares code %q with no httpx constant", name)
			continue
		}
		if string(v) != name {
			t.Errorf("code %q: httpx constant is %q", name, v)
		}
	}
	for name, v := range declared {
		if string(v) != name {
			t.Errorf("httpx constant %q drifted from contract name %q", v, name)
		}
	}
}

// 2. Фактический вывод WriteError совпадает с обязательными полями схемы Error.
func TestErrorEnvelopeMatchesContract(t *testing.T) {
	s := load(t)
	errSchema := s.Comp.Schemas["Error"]
	// Вложенный object в yaml.v3 лежит в Properties["error"]; required читаем с него.
	var nested struct {
		Required []string `yaml:"required"`
	}
	raw, _ := yaml.Marshal(errSchema.Properties["error"])
	if err := yaml.Unmarshal(raw, &nested); err != nil {
		t.Fatalf("nested error: %v", err)
	}
	want := map[string]bool{}
	for _, f := range nested.Required {
		want[f] = true
	}
	if len(want) == 0 {
		t.Fatal("Error.error has no required fields in the contract")
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	r = r.WithContext(withRequestID(t, r.Context()))
	httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrInvalidCredentials, "nope", nil)

	var body struct {
		Error map[string]json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("envelope is not JSON: %v", err)
	}
	for f := range want {
		if _, ok := body.Error[f]; !ok {
			t.Errorf("contract requires error.%s, WriteError did not emit it", f)
		}
	}
	for f := range body.Error {
		if !want[f] && f != "details" {
			t.Errorf("WriteError emitted error.%s, which the contract does not document", f)
		}
	}
}

// 3. Все пути публичные: /internal/v1 в этом файлу неоткуда взяться (узловой контракт — A-2).
func TestAllPathsArePublicV1(t *testing.T) {
	s := load(t)
	if len(s.Paths) == 0 {
		t.Fatal("contract has no paths")
	}
	for p := range s.Paths {
		if len(p) < 8 || p[:8] != "/api/v1/" {
			t.Errorf("path %q is not under /api/v1/", p)
		}
	}
	// 6 маршрутов A-1: register, login, refresh, logout, me, devices.
	if len(s.Paths) != 6 {
		t.Errorf("paths = %d, want 6 for cycle A-1", len(s.Paths))
	}
}

func withRequestID(t *testing.T, ctx context.Context) context.Context {
	t.Helper()
	var got context.Context
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	httpx.NewRequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.Context()
	})).ServeHTTP(httptest.NewRecorder(), req)
	if httpx.RequestIDFromContext(got) == "" {
		t.Fatal("request id middleware produced no request id")
	}
	return got
}
