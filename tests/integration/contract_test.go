//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/httpx"
)

// node — подмножество JSON Schema, которое действительно встречается в нашем контракте:
// type (скаляр или список), required, properties, items, enum, minimum, pattern,
// additionalProperties, $ref, allOf. Формат (date-time, uuid, email) здесь не
// проверяется сознательно: `format` — аннотация, а настоящие проверки дат и UUID делают
// time.Time и uuid при маршализации (задачи 15 и 17). maxLength/minLength тоже не
// проверяются: они относятся к телам ЗАПРОСОВ, а этот тест читает ответы.
type node struct {
	Ref   string `yaml:"$ref"`
	AllOf []node `yaml:"allOf"`
	Type  any    `yaml:"type"`
	// Значения в properties — всегда схемы (объекты), поэтому map[string]node, а не
	// map[string]any: раскодировка узлов происходит здесь, а не на уровне any.
	Required   []string        `yaml:"required"`
	Properties map[string]node `yaml:"properties"`
	Items      *node           `yaml:"items"`
	Enum       []any           `yaml:"enum"`
	Minimum    *float64        `yaml:"minimum"`
	Pattern    string          `yaml:"pattern"`
	// additionalProperties бывает и булевым, и схемой; здесь нужна только булева
	// форма («чужие поля запрещены»), а схемная форма в контракте не встречается.
	AdditionalProperties any `yaml:"additionalProperties"`
}

// response — описание кода ответа: либо $ref на components/responses, либо inline
// description+content. Ключ content — media type, внутри него схема.
type response struct {
	Ref         string `yaml:"$ref"`
	Description string `yaml:"description"`
	Content     map[string]struct {
		Schema node `yaml:"schema"`
	} `yaml:"content"`
}

// jsonSchema — схема application/json этого ответа. has=false означает «ответ без тела»
// (204), а не «контракт сломан»: путать эти два случая — значит валить тест на
// правильном коде.
func (r response) jsonSchema() (node, bool) {
	c, ok := r.Content["application/json"]
	if !ok {
		return node{}, false
	}
	return c.Schema, true
}

// operation — один метод одного пути; ключи YAML здесь строчные (post, get).
type operation struct {
	Responses map[string]response `yaml:"responses"`
}

type spec struct {
	Paths      map[string]map[string]operation `yaml:"paths"`
	Components struct {
		Schemas   map[string]node     `yaml:"schemas"`
		Responses map[string]response `yaml:"responses"`
	} `yaml:"components"`
}

func loadSpec(t *testing.T) *spec {
	t.Helper()
	// Тест живёт в tests/integration, контракт — в api-spec: два уровня вверх.
	raw, err := os.ReadFile("../../api-spec/openapi.yaml")
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	var s spec
	if err := yaml.Unmarshal(raw, &s); err != nil {
		t.Fatalf("parse contract: %v", err)
	}
	return &s
}

func (s *spec) resolve(ref string) (node, bool) {
	const p = "#/components/schemas/"
	if strings.HasPrefix(ref, p) {
		n, ok := s.Components.Schemas[strings.TrimPrefix(ref, p)]
		return n, ok
	}
	return node{}, false
}

// responseFor — описание кода ответа из контракта. $ref на components/responses
// разворачивается здесь же: иначе общая ошибка «InvalidRequest» была бы невидима для
// сверки, а именно таких в контракте большинство.
func (s *spec) responseFor(path, method string, status int) (response, bool) {
	op, ok := s.Paths[path][strings.ToLower(method)]
	if !ok {
		return response{}, false
	}
	resp, ok := op.Responses[strconv.Itoa(status)]
	if !ok {
		return response{}, false
	}
	if resp.Ref == "" {
		return resp, true
	}
	const r = "#/components/responses/"
	if !strings.HasPrefix(resp.Ref, r) {
		return response{}, false
	}
	target, ok := s.Components.Responses[strings.TrimPrefix(resp.Ref, r)]
	return target, ok
}

// validate проверяет значение по подмножеству схемы и возвращает список расхождений
// (пусто = соответствует). path — только для сообщения, чтобы провал показывал поле, а
// не «ответ не совпал».
func validate(n node, v any, s *spec, path string) []string {
	var out []string
	if len(n.Ref) > 0 {
		target, ok := s.resolve(n.Ref)
		if !ok {
			return []string{path + ": dangling $ref " + n.Ref}
		}
		return validate(target, v, s, path)
	}
	// allOf у нас используется ровно в одном виде: Error + уточнение enum для кода.
	// Каждая ветка проверяется по всему значению, поэтому порядок веток не важен.
	for _, sub := range n.AllOf {
		out = append(out, validate(sub, v, s, path)...)
	}

	types := []string{}
	switch t := n.Type.(type) {
	case string:
		types = []string{t}
	case []any:
		for _, x := range t {
			if str, ok := x.(string); ok {
				types = append(types, str)
			}
		}
	}
	if len(types) > 0 && !typeMatches(types, v) {
		return append(out, fmt.Sprintf("%s: value %T is not one of %v", path, v, types))
	}

	if len(n.Enum) > 0 {
		found := false
		for _, e := range n.Enum {
			if fmt.Sprint(e) == fmt.Sprint(v) {
				found = true
			}
		}
		if !found {
			out = append(out, fmt.Sprintf("%s: %v not in enum %v", path, v, n.Enum))
		}
	}

	switch val := v.(type) {
	case map[string]any:
		for _, req := range n.Required {
			if _, ok := val[req]; !ok {
				out = append(out, fmt.Sprintf("%s: missing required %q", path, req))
			}
		}
		for k, sub := range n.Properties {
			if x, ok := val[k]; ok {
				out = append(out, validate(sub, x, s, path+"."+k)...)
			}
		}
		if b, ok := n.AdditionalProperties.(bool); ok && !b {
			for k := range val {
				if _, declared := n.Properties[k]; !declared {
					out = append(out, fmt.Sprintf("%s: unexpected property %q", path, k))
				}
			}
		}
	case []any:
		if n.Items != nil {
			for i, x := range val {
				out = append(out, validate(*n.Items, x, s, fmt.Sprintf("%s[%d]", path, i))...)
			}
		}
	case float64:
		if n.Minimum != nil && val < *n.Minimum {
			out = append(out, fmt.Sprintf("%s: %v < minimum %v", path, val, *n.Minimum))
		}
	case string:
		if n.Pattern != "" {
			re, err := regexp.Compile(n.Pattern)
			if err != nil {
				out = append(out, path+": bad pattern in contract: "+err.Error())
			} else if !re.MatchString(val) {
				out = append(out, fmt.Sprintf("%s: %q does not match %s", path, val, n.Pattern))
			}
		}
	}
	return out
}

func typeMatches(types []string, v any) bool {
	for _, want := range types {
		switch want {
		case "object":
			if _, ok := v.(map[string]any); ok {
				return true
			}
		case "array":
			if _, ok := v.([]any); ok {
				return true
			}
		case "string":
			if _, ok := v.(string); ok {
				return true
			}
		case "integer":
			if f, ok := v.(float64); ok && f == float64(int64(f)) {
				return true
			}
		case "number":
			if _, ok := v.(float64); ok {
				return true
			}
		case "boolean":
			if _, ok := v.(bool); ok {
				return true
			}
		case "null":
			if v == nil {
				return true
			}
		}
	}
	return false
}

// liveCase — маршрут, до которого матрица умеет достучаться, и способ это сделать.
type liveCase struct {
	path, method string
	status       int
	run          func(t *testing.T, e *env) *http.Response
}

func TestLiveResponsesMatchContract(t *testing.T) {
	s := loadSpec(t)
	e := newEnv(t)

	cases := []liveCase{
		{"/api/v1/auth/register", http.MethodPost, 201, func(t *testing.T, e *env) *http.Response {
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/register",
				map[string]string{"email": "c-" + uuid.NewString()[:8] + "@novavpn.test",
					"password": testPassword}, nil)
			return r
		}},
		{"/api/v1/auth/register", http.MethodPost, 400, func(t *testing.T, e *env) *http.Response {
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/register",
				map[string]string{"email": "no-at-sign", "password": testPassword}, nil)
			return r
		}},
		{"/api/v1/auth/register", http.MethodPost, 409, func(t *testing.T, e *env) *http.Response {
			// Два вызова на один bucket: с двумя выше это четыре из пяти разрешённых,
			// и пятый случай на register в этом тесте уже не влезет.
			mail := "c-" + uuid.NewString()[:8] + "@novavpn.test"
			raw(t, e, http.MethodPost, "/api/v1/auth/register",
				map[string]string{"email": mail, "password": testPassword}, nil)
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/register",
				map[string]string{"email": mail, "password": testPassword}, nil)
			return r
		}},
		{"/api/v1/auth/login", http.MethodPost, 200, func(t *testing.T, e *env) *http.Response {
			a := e.mint(t)
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/login",
				map[string]string{"email": a.email, "password": seedPassword}, nil)
			return r
		}},
		{"/api/v1/auth/login", http.MethodPost, 401, func(t *testing.T, e *env) *http.Response {
			a := e.mint(t)
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/login",
				map[string]string{"email": a.email, "password": "wrong-password-123"}, nil)
			return r
		}},
		{"/api/v1/auth/login", http.MethodPost, 403, func(t *testing.T, e *env) *http.Response {
			a := e.block(t, e.mint(t))
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/login",
				map[string]string{"email": a.email, "password": seedPassword}, nil)
			return r
		}},
		{"/api/v1/auth/refresh", http.MethodPost, 200, func(t *testing.T, e *env) *http.Response {
			a := e.mint(t)
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/refresh",
				map[string]string{"refresh_token": a.refresh}, nil)
			return r
		}},
		{"/api/v1/auth/refresh", http.MethodPost, 401, func(t *testing.T, e *env) *http.Response {
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/refresh",
				map[string]string{"refresh_token": strings.Repeat("z", 48)}, nil)
			return r
		}},
		{"/api/v1/auth/refresh", http.MethodPost, 403, func(t *testing.T, e *env) *http.Response {
			a := e.block(t, e.mint(t))
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/refresh",
				map[string]string{"refresh_token": a.refresh}, nil)
			return r
		}},
		{"/api/v1/auth/logout", http.MethodPost, 204, func(t *testing.T, e *env) *http.Response {
			a := e.mint(t)
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/logout",
				map[string]string{"refresh_token": a.refresh}, nil)
			return r
		}},
		{"/api/v1/auth/logout", http.MethodPost, 401, func(t *testing.T, e *env) *http.Response {
			r, _ := raw(t, e, http.MethodPost, "/api/v1/auth/logout",
				map[string]string{"refresh_token": strings.Repeat("q", 48)}, nil)
			return r
		}},
		{"/api/v1/me", http.MethodGet, 200, func(t *testing.T, e *env) *http.Response {
			r, _ := raw(t, e, http.MethodGet, "/api/v1/me", nil, authHdr(e.mint(t).access))
			return r
		}},
		{"/api/v1/me", http.MethodGet, 401, func(t *testing.T, e *env) *http.Response {
			r, _ := raw(t, e, http.MethodGet, "/api/v1/me", nil, nil)
			return r
		}},
		{"/api/v1/devices", http.MethodPost, 201, func(t *testing.T, e *env) *http.Response {
			a := e.mint(t)
			r, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(21), "platform": "linux", "name": "c"},
				merge(authHdr(a.access), idem()))
			return r
		}},
		{"/api/v1/devices", http.MethodPost, 400, func(t *testing.T, e *env) *http.Response {
			a := e.mint(t)
			r, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(22), "platform": "linux", "name": "c"},
				authHdr(a.access))
			return r
		}},
		{"/api/v1/devices", http.MethodPost, 401, func(t *testing.T, e *env) *http.Response {
			r, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(23), "platform": "linux", "name": "c"},
				idem())
			return r
		}},
		{"/api/v1/devices", http.MethodPost, 403, func(t *testing.T, e *env) *http.Response {
			a := e.lapse(t, e.mint(t))
			r, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(24), "platform": "linux", "name": "c"},
				merge(authHdr(a.access), idem()))
			return r
		}},
		{"/api/v1/devices", http.MethodPost, 409, func(t *testing.T, e *env) *http.Response {
			a := e.mint(t)
			raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(25), "platform": "linux", "name": "c"},
				merge(authHdr(a.access), idem()))
			r, _ := raw(t, e, http.MethodPost, "/api/v1/devices",
				map[string]string{"public_key": keyAt(25), "platform": "linux", "name": "c"},
				merge(authHdr(a.access), idem()))
			return r
		}},
		{"/api/v1/devices", http.MethodGet, 200, func(t *testing.T, e *env) *http.Response {
			r, _ := raw(t, e, http.MethodGet, "/api/v1/devices", nil, authHdr(e.mint(t).access))
			return r
		}},
	}

	for _, c := range cases {
		t.Run(c.method+" "+c.path+" -> "+strconv.Itoa(c.status), func(t *testing.T) {
			doc, ok := s.responseFor(c.path, c.method, c.status)
			if !ok {
				t.Fatalf("contract documents neither %s %s nor its %d response",
					c.method, c.path, c.status)
			}
			schema, hasSchema := doc.jsonSchema()
			resp := c.run(t, e)
			if resp.StatusCode != c.status {
				t.Fatalf("live status = %d, case expects %d (%s)",
					resp.StatusCode, c.status, lastBody(t, e))
			}

			// Сквозные требования, которые контракт описывает, а код обязан держать.
			if id := resp.Header.Get("X-Request-Id"); !isHex16(id) {
				t.Errorf("X-Request-Id = %q, must be 16 hex chars on every response", id)
			}

			data := lastBody(t, e)
			if c.status == http.StatusNoContent {
				if hasSchema {
					t.Errorf("contract gives %d a schema, but 204 has no body", c.status)
				}
				if len(bytes.TrimSpace(data)) != 0 {
					t.Errorf("204 must have no body, got %s", data)
				}
				if ct := resp.Header.Get("Content-Type"); ct != "" {
					t.Errorf("204 must not declare Content-Type, got %q", ct)
				}
				return
			}
			if !hasSchema {
				t.Fatalf("contract declares no application/json schema for %d", c.status)
			}
			if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			var v any
			if err := json.Unmarshal(data, &v); err != nil {
				t.Fatalf("body is not JSON: %v (%s)", err, data)
			}
			where := fmt.Sprintf("%s %s %d", c.method, c.path, c.status)
			if problems := validate(schema, v, s, where); len(problems) > 0 {
				t.Errorf("response does not match contract:\n  %s\n  body: %s",
					strings.Join(problems, "\n  "), data)
			}
			if c.status >= 400 {
				checkErrorCodeKnown(t, v)
			}
		})
	}
}

// checkErrorCodeKnown: любой код, который живой сервер кладёт в конверт, обязан быть
// константой httpx, а значит — и значением из перечня контракта (равенство констант и
// перечня закрепляет TestContractCodesAreDeclared из задачи 16). Иначе клиент получает
// значение, которого «не существует».
func checkErrorCodeKnown(t *testing.T, v any) {
	t.Helper()
	obj, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("error body must be an object, got %T (%v)", v, v)
	}
	errNode, ok := obj["error"].(map[string]any)
	if !ok {
		t.Fatalf(`error body must have an "error" object: %v`, obj)
	}
	for _, k := range []string{"code", "message", "request_id"} {
		if _, ok := errNode[k]; !ok {
			t.Errorf("envelope is missing %q: %v", k, errNode)
		}
	}
	code, _ := errNode["code"].(string)
	for _, known := range []httpx.ErrorCode{
		httpx.ErrInvalidRequest, httpx.ErrUnauthenticated, httpx.ErrAccountLocked,
		httpx.ErrForbidden, httpx.ErrNotFound, httpx.ErrMethodNotAllowed,
		httpx.ErrConflict, httpx.ErrDeviceLimitReached, httpx.ErrDuplicateDevice,
		httpx.ErrIdempotencyKeyRequired, httpx.ErrIdempotencyConflict,
		httpx.ErrIdempotencyInProgress, httpx.ErrRateLimited, httpx.ErrInternal,
		httpx.ErrInvalidCredentials, httpx.ErrRefreshTokenInvalid, httpx.ErrEmailTaken,
	} {
		if string(known) == code {
			return
		}
	}
	t.Errorf("code %q is not a known httpx error code", code)
}

func lastBody(t *testing.T, e *env) []byte {
	t.Helper()
	if len(e.ev.calls) == 0 {
		t.Fatal("no requests captured")
	}
	return e.ev.calls[len(e.ev.calls)-1].body
}
