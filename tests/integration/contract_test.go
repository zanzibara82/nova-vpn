//go:build integration

package integration

import (
	"bytes"
	"context"
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
	// AnyOf встречается ровно у health в AdminServerDetail: Health либо null.
	// Проверяется как «совпала хотя бы одна ветка», остальное — по общим правилам.
	AnyOf []node `yaml:"anyOf"`
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

// jsonSchema — схема application/json этого ответа. has=false означает «ответ без
// JSON-тела» (204, 304 или text/plain), а не «контракт сломан»: путать эти случаи —
// значит валить тест на правильном коде.
func (r response) jsonSchema() (node, bool) {
	c, ok := r.Content["application/json"]
	if !ok {
		return node{}, false
	}
	return c.Schema, true
}

// textSchema — схема text/plain. Сейчас это только WireGuard-конфиг: тело — строка,
// и разбирать её как JSON нечем и незачем.
func (r response) textSchema() (node, bool) {
	c, ok := r.Content["text/plain"]
	if !ok {
		return node{}, false
	}
	return c.Schema, true
}

// operation — один метод одного пути; ключи YAML здесь строчные (post, get).
type operation struct {
	Responses map[string]response `yaml:"responses"`
}

// pathItem — элемент paths. Кроме методов у шаблонных путей есть общий список
// parameters: это не операция, и без отдельного поля раскодировка падала бы на
// попытке превратить последовательность в operation.
type pathItem struct {
	Parameters []any `yaml:"parameters"`
	// Остальные ключи пути — методы; строчные имена совпадают с http.Method* в
	// нижнем регистре (get, post, patch, delete).
	Methods map[string]operation `yaml:",inline"`
}

type spec struct {
	Paths      map[string]pathItem `yaml:"paths"`
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
	item, ok := s.Paths[path]
	if !ok {
		return response{}, false
	}
	op, ok := item.Methods[strings.ToLower(method)]
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
	// anyOf требует совпадения хотя бы одной ветки. Провал одной ветки не ошибка,
	// поэтому ветки проверяются отдельно, а наружу выходит одно расхождение.
	if len(n.AnyOf) > 0 {
		matched := false
		for _, sub := range n.AnyOf {
			if len(validate(sub, v, s, path)) == 0 {
				matched = true
				break
			}
		}
		if !matched {
			out = append(out, fmt.Sprintf("%s: value %v matches none of anyOf", path, v))
		}
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

	// Один профиль на все чтения: выдача стоит POST, а список, один профиль и текст
	// конфига читают одно и то же состояние. Отдельный профиль нужен отзыву — он
	// меняет состояние, и общая фикстура сделала бы DELETE зависимым от порядка.
	var readFixture *profileFixture
	readProfile := func(t *testing.T) profileFixture {
		t.Helper()
		if readFixture == nil {
			f := e.withProfile(t)
			readFixture = &f
		}
		return *readFixture
	}

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

		// --- A-2: каталог ---
		{"/api/v1/servers", http.MethodGet, 200, func(t *testing.T, e *env) *http.Response {
			// Каталог отдаёт только online-серверы; фикстура гарантирует непустой
			// список, иначе обязательные поля ServerSummary проверялись бы на нуле
			// элементов. Тройка «не измерено» обязана быть в объекте ключами со
			// значением null, а не отсутствовать.
			e.server(t)
			resp, body := raw(t, e, http.MethodGet, "/api/v1/servers", nil, authHdr(e.mint(t).access))
			var out struct {
				Servers []map[string]json.RawMessage `json:"servers"`
			}
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatalf("servers body: %v (%s)", err, body)
			}
			if len(out.Servers) == 0 {
				t.Fatalf("каталог пуст: форму ServerSummary не на чем проверить")
			}
			for _, srv := range out.Servers {
				for _, k := range []string{"latency_ms", "load", "capacity_mbps"} {
					v, ok := srv[k]
					if !ok {
						t.Errorf("ServerSummary без %q: %v", k, srv)
					} else if string(bytes.TrimSpace(v)) != "null" {
						t.Errorf("ServerSummary.%s = %s, контрол-плейн его не измерял", k, v)
					}
				}
			}
			return resp
		}},

		// --- A-2: профили ---
		{"/api/v1/devices/{id}/profiles", http.MethodPost, 201, func(t *testing.T, e *env) *http.Response {
			a := e.mint(t)
			d := seedDevice(t, context.Background(), e.q, a.userID, 1)
			srv := e.server(t)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices/"+d.ID.String()+"/profiles",
				map[string]string{"server_id": srv.ID.String()}, merge(authHdr(a.access), idem()))
			return resp
		}},
		{"/api/v1/devices/{id}/profiles", http.MethodPost, 403, func(t *testing.T, e *env) *http.Response {
			a := e.lapse(t, e.mint(t))
			d := seedDevice(t, context.Background(), e.q, a.userID, 1)
			srv := e.server(t)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices/"+d.ID.String()+"/profiles",
				map[string]string{"server_id": srv.ID.String()}, merge(authHdr(a.access), idem()))
			return resp
		}},
		{"/api/v1/devices/{id}/profiles", http.MethodPost, 409, func(t *testing.T, e *env) *http.Response {
			// Maintenance-сервер по умолчанию (seedServer): выдача обязана ответить
			// стабильным кодом server_not_available, а не 503 «повтори позже».
			a := e.mint(t)
			d := seedDevice(t, context.Background(), e.q, a.userID, 1)
			srv := seedServer(t, context.Background(), e.q, "10.99.95.0/24")
			resp, body := raw(t, e, http.MethodPost, "/api/v1/devices/"+d.ID.String()+"/profiles",
				map[string]string{"server_id": srv.ID.String()}, merge(authHdr(a.access), idem()))
			if code := codeOf(t, body); resp.StatusCode == http.StatusConflict && code != "server_not_available" {
				t.Fatalf("409 code = %q, want server_not_available (%s)", code, body)
			}
			return resp
		}},
		{"/api/v1/devices/{id}/profiles", http.MethodGet, 200, func(t *testing.T, e *env) *http.Response {
			f := readProfile(t)
			resp, _ := raw(t, e, http.MethodGet, f.profilePath(e), nil, authHdr(f.actor.access))
			return resp
		}},
		{"/api/v1/devices/{id}/profiles/{server_id}", http.MethodGet, 200, func(t *testing.T, e *env) *http.Response {
			f := readProfile(t)
			resp, _ := raw(t, e, http.MethodGet, f.onePath(), nil, authHdr(f.actor.access))
			return resp
		}},
		{"/api/v1/devices/{id}/profiles/{server_id}", http.MethodDelete, 204, func(t *testing.T, e *env) *http.Response {
			f := e.withProfile(t)
			resp, _ := raw(t, e, http.MethodDelete, f.onePath(), nil, authHdr(f.actor.access))
			return resp
		}},
		{"/api/v1/devices/{id}/profiles/{server_id}/config", http.MethodGet, 200, func(t *testing.T, e *env) *http.Response {
			f := readProfile(t)
			resp, _ := raw(t, e, http.MethodGet, f.onePath()+"/config", nil, authHdr(f.actor.access))
			return resp
		}},
		{"/api/v1/devices/{id}/keys/rotate", http.MethodPost, 200, func(t *testing.T, e *env) *http.Response {
			// Контракт объявляет здесь Device, а не отдельную RotateResponse: план
			// называл несуществующую схему, сверяемся с контрактом.
			a := e.mint(t)
			d := seedDevice(t, context.Background(), e.q, a.userID, 1)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/devices/"+d.ID.String()+"/keys/rotate",
				map[string]string{"public_key": keyFromSeed("contract-rotate-" + uuid.NewString())},
				merge(authHdr(a.access), idem()))
			return resp
		}},

		// --- A-2: контракт узла ---
		{"/internal/v1/nodes/{server_id}/desired", http.MethodGet, 200, func(t *testing.T, e *env) *http.Response {
			own := e.node(t, e.server(t).ID)
			resp, _ := raw(t, e, http.MethodGet, nodePath(own.serverID, "/desired"), nil,
				authHdr(own.token))
			if etag := resp.Header.Get("ETag"); etag == "" {
				t.Errorf("desired set answer has no ETag")
			}
			return resp
		}},
		{"/internal/v1/nodes/{server_id}/desired", http.MethodGet, 304, func(t *testing.T, e *env) *http.Response {
			// Второй вызов того же узла: ETag предыдущего ответа обязан дать 304 без
			// тела. Строгое сравнение проверяет сам хендлер, здесь — живой ответ.
			own := e.node(t, e.server(t).ID)
			path := nodePath(own.serverID, "/desired")
			first, _ := raw(t, e, http.MethodGet, path, nil, authHdr(own.token))
			etag := first.Header.Get("ETag")
			if first.StatusCode != http.StatusOK || etag == "" {
				t.Fatalf("desired 200 = %d, ETag = %q", first.StatusCode, etag)
			}
			resp, _ := raw(t, e, http.MethodGet, path, nil,
				merge(authHdr(own.token), map[string]string{"If-None-Match": etag}))
			return resp
		}},
		{"/internal/v1/nodes/{server_id}/observed", http.MethodPost, 204, func(t *testing.T, e *env) *http.Response {
			own := e.node(t, e.server(t).ID)
			resp, _ := raw(t, e, http.MethodPost, nodePath(own.serverID, "/observed"),
				map[string]any{"config_version": 0, "interface_rx_bytes": 0,
					"interface_tx_bytes": 0, "peers": []any{}},
				authHdr(own.token))
			return resp
		}},
		{"/internal/v1/nodes/{server_id}/heartbeat", http.MethodPost, 204, func(t *testing.T, e *env) *http.Response {
			own := e.node(t, e.server(t).ID)
			resp, _ := raw(t, e, http.MethodPost, nodePath(own.serverID, "/heartbeat"),
				map[string]any{"agent_version": "contract", "agent_uptime_sec": 1,
					"load1": 0.1, "cpu_pct": 1.0, "applied_config_version": 0},
				authHdr(own.token))
			return resp
		}},

		// --- A-2: администратор ---
		{"/api/v1/admin/login", http.MethodPost, 200, func(t *testing.T, e *env) *http.Response {
			// Отдельный администратор, а не e.admin: тот кэширует токен, иначе первая
			// же строка контура съедала бы ответ входа, который здесь и проверяется.
			_, email := seedAdmin(t, context.Background(), e.q)
			resp, _ := raw(t, e, http.MethodPost, "/api/v1/admin/login",
				map[string]string{"email": email, "password": adminPassword}, nil)
			return resp
		}},
		{"/api/v1/admin/servers/{id}", http.MethodGet, 200, func(t *testing.T, e *env) *http.Response {
			// Свежезаведённый сервер никогда не отвечал heartbeat'ом: health обязан
			// быть null, а не нулями (§13.4).
			srv := seedServer(t, context.Background(), e.q, "10.99.95.0/24")
			resp, body := raw(t, e, http.MethodGet, "/api/v1/admin/servers/"+srv.ID.String(), nil,
				authHdr(e.admin(t).token))
			var out map[string]json.RawMessage
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatalf("admin server body: %v (%s)", err, body)
			}
			health, ok := out["health"]
			if !ok {
				t.Errorf(`admin server answer has no "health": %s`, body)
			} else if string(bytes.TrimSpace(health)) != "null" {
				t.Errorf("health = %s, want null: замера не было", health)
			}
			return resp
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
			_, hasText := doc.textSchema()
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
			// 204 и 304 — ответы без тела; в контракте у них нет content. Для 304 это
			// единственный такой случай, и JSON в нём искать не нужно.
			if c.status == http.StatusNoContent || c.status == http.StatusNotModified {
				if hasSchema || hasText {
					t.Errorf("contract gives %d a schema, but it has no body", c.status)
				}
				if len(bytes.TrimSpace(data)) != 0 {
					t.Errorf("%d must have no body, got %s", c.status, data)
				}
				if ct := resp.Header.Get("Content-Type"); ct != "" {
					t.Errorf("%d must not declare Content-Type, got %q", c.status, ct)
				}
				return
			}
			if hasText {
				// text/plain — конфиг WireGuard. JSON-схемы у него нет, а приватного
				// ключа быть не должно ни при каких обстоятельствах (ТЗ §5, §19.6):
				// клиент вставляет его локально, сервер его не знает.
				if hasSchema {
					t.Errorf("contract declares both JSON and text/plain for %d", c.status)
				}
				if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
					t.Errorf("Content-Type = %q, want text/plain", ct)
				}
				if len(bytes.TrimSpace(data)) == 0 {
					t.Errorf("text/plain answer is empty")
				}
				if strings.Contains(strings.ToLower(string(data)), "privatekey") {
					t.Errorf("config body contains PrivateKey: %s", data)
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
		httpx.ErrServerNotAvailable,
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
