package api_spec_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
		"server_not_available":        httpx.ErrServerNotAvailable,
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

// 3. Множество путей — контракт целиком: семейство A-1 (идентификация, сессии,
// устройства) плюс A-2 (каталог, профили, admin, узел). Список литеральный, а не
// число: число не говорит, какой именно путь потеряли. Каждый путь обязан попадать
// ровно в один префикс — публичный /api/v1/ или внутренний /internal/v1/; третий
// префикс означал бы маршрут, для которого не решено, кто имеет право спрашивать.
func TestPathsArePartitioned(t *testing.T) {
	s := load(t)
	want := []string{
		// A-1.
		"/api/v1/auth/register",
		"/api/v1/auth/login",
		"/api/v1/auth/refresh",
		"/api/v1/auth/logout",
		"/api/v1/me",
		"/api/v1/devices",
		// A-2, публичные.
		"/api/v1/servers",
		"/api/v1/devices/{id}",
		"/api/v1/devices/{id}/keys/rotate",
		"/api/v1/devices/{id}/profiles",
		"/api/v1/devices/{id}/profiles/{server_id}",
		"/api/v1/devices/{id}/profiles/{server_id}/config",
		// A-2, admin.
		"/api/v1/admin/login",
		"/api/v1/admin/servers",
		"/api/v1/admin/servers/{id}",
		"/api/v1/admin/servers/{id}/maintenance",
		"/api/v1/admin/servers/{id}/bootstrap-tokens",
		"/api/v1/admin/bootstrap-tokens/{id}",
		"/api/v1/admin/servers/{id}/node-token/revoke",
		"/api/v1/admin/users/{id}",
		"/api/v1/admin/users/{id}/lock",
		"/api/v1/admin/users/{id}/unlock",
		"/api/v1/admin/admins",
		"/api/v1/admin/audit",
		// A-2, узел.
		"/internal/v1/nodes/enroll",
		"/internal/v1/nodes/{server_id}/desired",
		"/internal/v1/nodes/{server_id}/observed",
		"/internal/v1/nodes/{server_id}/heartbeat",
		"/internal/v1/nodes/{server_id}/token/rotate",
	}
	got := make(map[string]bool, len(s.Paths))
	for p := range s.Paths {
		got[p] = true
	}
	for _, p := range want {
		if !got[p] {
			t.Errorf("contract lost path %q", p)
		}
		delete(got, p)
	}
	for p := range got {
		t.Errorf("contract has path %q, which is not in the A-2 list", p)
	}
	for _, p := range want {
		public := strings.HasPrefix(p, "/api/v1/")
		internal := strings.HasPrefix(p, "/internal/v1/")
		if public == internal {
			t.Errorf("path %q is not under exactly one of /api/v1/ or /internal/v1/", p)
		}
	}
}

// 4. «Кто имеет право спрашивать» — часть контракта, а не догадка клиента. Внутренние
// маршруты узла принимают только nodeBearerAuth, админские — только adminBearerAuth;
// enroll и admin/login анонимны по построению: у узла ещё нет токена, у админа — ещё
// нет сессии. Смысл проверки в том, что два `iss` в токенах раздельные, и контракт
// обязан это показывать явно.
func TestInternalPathsUseNodeScheme(t *testing.T) {
	s := load(t)
	for path, ops := range s.Paths {
		for method, raw := range ops {
			op, ok := raw.(map[string]any)
			if !ok {
				continue // параметры уровня пути, не операция
			}
			names, present := securitySchemes(op)
			switch {
			case path == "/internal/v1/nodes/enroll", path == "/api/v1/admin/login":
				if !present || len(names) != 0 {
					t.Errorf("%s %s: анонимный маршрут обязан объявить security: [], получено %v (present=%v)",
						method, path, names, present)
				}
			case strings.HasPrefix(path, "/internal/v1/"):
				if !present || len(names) != 1 || names[0] != "nodeBearerAuth" {
					t.Errorf("%s %s: нужен security: [{nodeBearerAuth: []}], получено %v (present=%v)",
						method, path, names, present)
				}
			case strings.HasPrefix(path, "/api/v1/admin/"):
				if !present || len(names) != 1 || names[0] != "adminBearerAuth" {
					t.Errorf("%s %s: нужен security: [{adminBearerAuth: []}], получено %v (present=%v)",
						method, path, names, present)
				}
			}
		}
	}
}

// securitySchemes читает security операции как список имён схем. present=false
// означает «поле не объявлено вовсе» — это не то же самое, что security: [].
func securitySchemes(op map[string]any) (names []string, present bool) {
	raw, ok := op["security"]
	if !ok {
		return nil, false
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, false
	}
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, false
		}
		for name := range m {
			names = append(names, name)
		}
	}
	return names, true
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
