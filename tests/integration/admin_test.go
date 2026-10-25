//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/audit"
	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/servers"
)

// adminPassword — пароль фикстуры. Длиннее auth.MinPasswordLen и с дефисом:
// проверка «короткий пароль отклоняется» обязана отличаться от этой строки, иначе
// она отвергала бы и стенд.
const adminPassword = "integration-admin-password-1"

// adminStand — стенд администратора на настоящем сборщике маршрутов (тот же
// newRouter, что задача 11): конверт, лимитеры, журнал и 404/405 продовым.
// token пуст до withToken: тесты отказа входа не должны зависеть от удачного входа.
type adminStand struct {
	base   string
	logs   *bytes.Buffer
	ctx    context.Context
	q      *db.Queries
	admin  uuid.UUID
	email  string
	server db.VpnServer
	token  string
}

func seedAdmin(t *testing.T, ctx context.Context, q *db.Queries) (uuid.UUID, string) {
	t.Helper()
	id := uuid.New()
	hash, err := auth.HashPassword(adminPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	row, err := q.InsertAdminUser(ctx, db.InsertAdminUserParams{
		ID: id, Email: "admin-" + id.String()[:8] + "@novavpn.test", PasswordHash: hash,
	})
	if err != nil {
		t.Fatalf("InsertAdminUser: %v", err)
	}
	return row.ID, row.Email
}

// newAdminStand — сервер в online и админ. Админский токен здесь сознательно НЕ
// получен: маршрут входа проверяется отдельно, и тест отказа обязан работать без
// предположения, что вход вообще существует.
func newAdminStand(t *testing.T) adminStand {
	t.Helper()
	srv, logs := newRouter(t)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	t.Cleanup(cancel)
	q := db.New(pool(t))
	server := seedServer(t, ctx, q, "10.99.70.0/24")
	setServerOnline(t, ctx, q, server.ID)
	admin, email := seedAdmin(t, ctx, q)
	return adminStand{base: srv.URL, logs: logs, ctx: ctx, q: q, admin: admin, email: email, server: server}
}

// adminToken — вход через настоящий маршрут, а не через Issuer напрямую: иначе
// проверка «токен админа принимается роутером» проверяла бы сам тест.
func adminToken(t *testing.T, s adminStand) string {
	t.Helper()
	tok := loginAdmin(t, s.base, s.email, adminPassword)
	s.token = tok
	return tok
}

func loginAdmin(t *testing.T, base, email, password string) string {
	t.Helper()
	resp, body := do(t, http.MethodPost, base+"/api/v1/admin/login",
		map[string]string{"email": email, "password": password}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("вход админа = %d %v, want 200", resp.StatusCode, body)
	}
	if tt, _ := body["token_type"].(string); tt != "bearer" {
		t.Errorf("token_type = %q, want bearer", tt)
	}
	tok, _ := body["access_token"].(string)
	if tok == "" {
		t.Fatalf("в ответе входа нет access_token: %v", body)
	}
	return tok
}

// env — стенд с полученным токеном: почти всем тестам нужен вход, а разница между
// «вход есть» и «маршрут входа существует» проверена в TestAdminLoginOracle.
func (s adminStand) env(t *testing.T) adminStand {
	t.Helper()
	s.token = adminToken(t, s)
	return s
}

// call — запрос к тому же стенду с админским токеном; path начинается с /api/v1/admin.
func (s adminStand) call(t *testing.T, method, path string, body any) (*http.Response, map[string]any) {
	t.Helper()
	return do(t, method, s.base+path, body, s.token)
}

// requestID — X-Request-Id ответа: middleware проставляет его на любой ответ, и
// аудит сверяется по нему, а не по тексту.
func requestID(t *testing.T, resp *http.Response) string {
	t.Helper()
	id := resp.Header.Get("X-Request-Id")
	if !isHex16(id) {
		t.Fatalf("X-Request-Id = %q, want 16 hex chars", id)
	}
	return id
}

func jsonArray(t *testing.T, body map[string]any, key string) []map[string]any {
	t.Helper()
	raw, err := json.Marshal(body[key])
	if err != nil {
		t.Fatalf("marshal %q: %v", key, err)
	}
	var out []map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("body[%q] не массив объектов: %v", key, body)
	}
	return out
}

func pickByID(t *testing.T, items []map[string]any, id string) map[string]any {
	t.Helper()
	for _, it := range items {
		if it["id"] == id {
			return it
		}
	}
	t.Fatalf("среди %d записей нет id=%s", len(items), id)
	return nil
}

// auditOf — последние записи аудита, отфильтрованные по действию. Берём из базы, а
// не из ответа: журнал аудита обязан читаться и там, где его никто не запрашивал.
func auditOf(t *testing.T, ctx context.Context, q *db.Queries, action db.AuditAction, targetID string) []db.AdminAuditLog {
	t.Helper()
	rows, err := q.RecentAdminAudit(ctx, db.RecentAdminAuditParams{Limit: 500, Offset: 0})
	if err != nil {
		t.Fatalf("RecentAdminAudit: %v", err)
	}
	var out []db.AdminAuditLog
	for _, r := range rows {
		if r.Action == action && (targetID == "" || r.TargetID == targetID) {
			out = append(out, r)
		}
	}
	return out
}

func countQuery(t *testing.T, ctx context.Context, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool(t).QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", sql, err)
	}
	return n
}

// journalReasons — сколько раз указанная причина админского отказа попала в журнал.
func journalReasons(t *testing.T, logs string, reason string) int {
	t.Helper()
	return strings.Count(logs, `"reason":"`+reason+`"`)
}

func TestAdminLoginOracleAndRoleSeparation(t *testing.T) {
	s := newAdminStand(t)

	// Неизвестный email и неверный пароль того же email: ответы обязаны совпасть
	// байтово (пара code|message и код), иначе маршрут стал бы оракулом «есть ли
	// такой админ».
	ghost := "ghost-" + uuid.NewString()[:8] + "@novavpn.test"
	r1, b1 := do(t, http.MethodPost, s.base+"/api/v1/admin/login",
		map[string]string{"email": ghost, "password": adminPassword}, "")
	r2, b2 := do(t, http.MethodPost, s.base+"/api/v1/admin/login",
		map[string]string{"email": s.email, "password": "wrong-but-long-enough-1"}, "")
	if r1.StatusCode != http.StatusUnauthorized || r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("статусы = %d и %d, want 401 и 401", r1.StatusCode, r2.StatusCode)
	}
	if errorCode(t, b1) != "invalid_credentials" || errorCode(t, b2) != "invalid_credentials" {
		t.Errorf("коды = %v / %v, want invalid_credentials", b1, b2)
	}
	if envelopePair(b1) != envelopePair(b2) {
		t.Errorf("ответы различимы: %q против %q — маршрут стал оракулом", envelopePair(b1), envelopePair(b2))
	}
	// А в журнале причины обязаны быть разными: «никто не пришёл» и «пришёл не с тем
	// паролем» для оператора — разные события.
	if n := journalReasons(t, s.logs.String(), "unknown_email"); n != 1 {
		t.Errorf("строк с reason=unknown_email = %d, want 1", n)
	}
	if n := journalReasons(t, s.logs.String(), "bad_password"); n != 1 {
		t.Errorf("строк с reason=bad_password = %d, want 1", n)
	}

	// Без токена и с пользовательским токеном — 401; с админским — 200. Тот же
	// разбор, что unit-тест шага 2, но сквозь HTTP: собирает ли сборщик второй Issuer.
	if resp, body := do(t, http.MethodGet, s.base+"/api/v1/admin/servers", nil, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("без токена = %d %v, want 401", resp.StatusCode, body)
	}
	userEmail := "user-" + uuid.NewString()[:8] + "@novavpn.test"
	resp, body := do(t, http.MethodPost, s.base+"/api/v1/auth/register",
		map[string]string{"email": userEmail, "password": testPassword}, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register = %d %v, want 201", resp.StatusCode, body)
	}
	userToken, _ := body["access_token"].(string)
	if userToken == "" {
		t.Fatalf("в регистрации нет access_token: %v", body)
	}
	resp, body = do(t, http.MethodGet, s.base+"/api/v1/admin/servers", nil, userToken)
	if resp.StatusCode != http.StatusUnauthorized || errorCode(t, body) != "unauthenticated" {
		t.Errorf("пользовательский токен на admin-маршруте = %d %v, want 401 unauthenticated", resp.StatusCode, body)
	}

	tok := adminToken(t, s)
	resp, body = do(t, http.MethodGet, s.base+"/api/v1/admin/servers", nil, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("админский токен = %d %v, want 200", resp.StatusCode, body)
	}
	// И обратно: админский токен не открывает пользовательский маршрут. Разделение
	// двустороннее, иначе /api/v1/devices обслуживался бы субъектом другого класса.
	if resp, body := do(t, http.MethodGet, s.base+"/api/v1/devices", nil, tok); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("админский токен на /devices = %d %v, want 401", resp.StatusCode, body)
	}

	// expires_in — секунды того же TTL, что и у токена, а не отдельное число.
	resp, body = do(t, http.MethodPost, s.base+"/api/v1/admin/login",
		map[string]string{"email": s.email, "password": adminPassword}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("успешный вход = %d %v", resp.StatusCode, body)
	}
	if expiresIn, _ := body["expires_in"].(float64); expiresIn != 600 {
		t.Errorf("expires_in = %v, want 600 (AccessTTL стенда — 10 минут)", expiresIn)
	}
	if _, ok := body["admin_id"]; ok {
		t.Error("ответ входа содержит admin_id: id админа уже есть в sub токена, второй источник разойдётся")
	}
}

func TestAdminServersListShowsPeersActive(t *testing.T) {
	s := newAdminStand(t)
	user := seedUser(t, s.ctx, s.q, true)
	device := seedDevice(t, s.ctx, s.q, user, 0)
	seedProfile(t, s.ctx, s.q, device.ID, s.server.ID, "10.99.70.2", time.Hour)

	s = s.env(t)
	resp, body := s.call(t, http.MethodGet, "/api/v1/admin/servers", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /servers = %d %v, want 200", resp.StatusCode, body)
	}
	row := pickByID(t, jsonArray(t, body, "servers"), s.server.ID.String())
	if got := row["peers_active"]; got != float64(1) {
		t.Errorf("peers_active = %v, want 1 (один active-профиль на сервере)", got)
	}
	if row["maintenance_status"] != "online" {
		t.Errorf("maintenance_status = %v, want online", row["maintenance_status"])
	}
	// Пул — строкой: netip.Prefix наружу отдаётся в форме, которую читает человек, а
	// не как объект из двух полей.
	if row["address_pool_v4"] != "10.99.70.0/24" {
		t.Errorf("address_pool_v4 = %v, want \"10.99.70.0/24\"", row["address_pool_v4"])
	}
}

// newServerBody — корректное тело POST /servers: локация, хост, порт, ключ и пул.
// mtu/keepalive/capacity отсутствуют намеренно — дефолты проверяются отдельным
// утверждением, а не молчаливым повтором в запросе.
func newServerBody(name, city, poolV4, publicKey string) map[string]any {
	return map[string]any{
		"location": map[string]any{
			"country_code": "DE", "city": city,
			"lat": "52.5200", "lon": "13.4050", "timezone": "Europe/Berlin",
		},
		"name": name, "advertised_host": "203.0.113.7", "listen_port": 51830,
		"public_key": publicKey, "address_pool_v4": poolV4, "provider": "admin-test",
	}
}

func TestAdminCreateServer(t *testing.T) {
	s := newAdminStand(t).env(t)
	name := "adm-" + uuid.NewString()[:8]
	city := "nuremberg-" + uuid.NewString()[:8]
	key := keyFromSeed("admin-created-" + uuid.NewString())

	resp, body := s.call(t, http.MethodPost, "/api/v1/admin/servers",
		newServerBody(name, city, "10.99.80.0/24", key))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /servers = %d %v, want 201", resp.StatusCode, body)
	}
	if body["maintenance_status"] != "maintenance" {
		t.Errorf("maintenance_status = %v, want maintenance (зарегистрирован ≠ работает)", body["maintenance_status"])
	}
	if body["config_version"] != float64(0) {
		t.Errorf("config_version = %v, want 0", body["config_version"])
	}
	if body["public_key"] != key {
		t.Errorf("public_key = %v, want каноническая форма %v", body["public_key"], key)
	}
	created, _ := body["id"].(string)
	if created == "" {
		t.Fatalf("в ответе нет id: %v", body)
	}
	// Та же локаль, что у второго сервера: UNIQUE (country_code, city, lat, lon) в
	// схеме, а код обязан искать её, а не вставлять дубль и ловить 500.
	second := "adm2-" + uuid.NewString()[:8]
	resp, body = s.call(t, http.MethodPost, "/api/v1/admin/servers",
		newServerBody(second, city, "10.99.81.0/24", keyFromSeed("admin-created-2-"+uuid.NewString())))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("второй POST /servers = %d %v, want 201", resp.StatusCode, body)
	}
	if n := countQuery(t, s.ctx, "SELECT count(*) FROM server_locations WHERE city = $1", city); n != 1 {
		t.Errorf("строк локации %s = %d, want 1", city, n)
	}
	if n := countQuery(t, s.ctx, "SELECT count(*) FROM admin_audit_logs WHERE action = 'server_created' AND target_id = $1", created); n != 1 {
		t.Errorf("записей server_created = %d, want 1", n)
	}
	// Значения по умолчанию зафиксированы ответом: mtu/keepalive не присылались.
	if body["mtu"] != float64(1420) || body["keepalive_sec"] != float64(25) {
		t.Errorf("defaults = %v/%v, want 1420/25", body["mtu"], body["keepalive_sec"])
	}
}

func TestAdminCreateServerRejectsBadPayloads(t *testing.T) {
	s := newAdminStand(t).env(t)

	// Неканонический ключ: взведены spare-биты последнего символа base64 — та же
	// форма, которую отвергает регистрация устройства (nonCanonicalKey в rotation_test.go).
	nonCanonical := nonCanonicalKey("admin-non-canonical-" + uuid.NewString())
	resp, body := s.call(t, http.MethodPost, "/api/v1/admin/servers",
		newServerBody("bad-key-"+uuid.NewString()[:8], "kk-"+uuid.NewString()[:8], "10.99.82.0/24", nonCanonical))
	if resp.StatusCode != http.StatusBadRequest || errorCode(t, body) != "invalid_request" {
		t.Fatalf("неканонический ключ = %d %v, want 400 invalid_request", resp.StatusCode, body)
	}
	if field := envelopeDetailsField(t, body); field != "public_key" {
		t.Errorf("details.field = %q, want public_key", field)
	}

	// /23 — не «узел на 512 клиентов», а пул, который аллокатор перебирает половину
	// пространства до первого отказа.
	resp, body = s.call(t, http.MethodPost, "/api/v1/admin/servers",
		newServerBody("bad-pool-"+uuid.NewString()[:8], "pp-"+uuid.NewString()[:8], "10.99.0.0/23",
			keyFromSeed("bad-pool-"+uuid.NewString())))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("пул /23 = %d %v, want 400", resp.StatusCode, body)
	}
	if field := envelopeDetailsField(t, body); field != "address_pool_v4" {
		t.Errorf("details.field = %q, want address_pool_v4", field)
	}

	// Дубликат имени: UNIQUE на vpn_servers.name — конфликт, а не 500.
	name := "dup-" + uuid.NewString()[:8]
	if resp, body := s.call(t, http.MethodPost, "/api/v1/admin/servers",
		newServerBody(name, "dd-"+uuid.NewString()[:8], "10.99.83.0/24", keyFromSeed("dup-1-"+name))); resp.StatusCode != http.StatusCreated {
		t.Fatalf("первый сервер = %d %v, want 201", resp.StatusCode, body)
	}
	resp, body = s.call(t, http.MethodPost, "/api/v1/admin/servers",
		newServerBody(name, "ee-"+uuid.NewString()[:8], "10.99.84.0/24", keyFromSeed("dup-2-"+name)))
	if resp.StatusCode != http.StatusConflict || errorCode(t, body) != "conflict" {
		t.Errorf("дубликат имени = %d %v, want 409 conflict", resp.StatusCode, body)
	}
}

func envelopeDetailsField(t *testing.T, body map[string]any) string {
	t.Helper()
	e, _ := body["error"].(map[string]any)
	d, _ := e["details"].(map[string]any)
	field, _ := d["field"].(string)
	return field
}

func TestAdminPatchAndMaintenanceAndDelete(t *testing.T) {
	s := newAdminStand(t).env(t)
	name := "patch-" + uuid.NewString()[:8]
	resp, created := s.call(t, http.MethodPost, "/api/v1/admin/servers",
		newServerBody(name, "pt-"+uuid.NewString()[:8], "10.99.85.0/24", keyFromSeed("patch-"+name)))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("создание = %d %v", resp.StatusCode, created)
	}
	id, _ := created["id"].(string)
	path := "/api/v1/admin/servers/" + id

	// Деталь: здоровья нет → null, а не нули. Неизмеренное остаётся неизмеренным.
	resp, detail := s.call(t, http.MethodGet, path, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /servers/{id} = %d %v", resp.StatusCode, detail)
	}
	if h, ok := detail["health"]; !ok || h != nil {
		t.Errorf("health = %v, want null", detail["health"])
	}
	// Версию при правке читает админ из ответа; узел получает её bump'ом — проверка
	// ниже идёт через servers.Compute, а не по телу ответа.
	before := detail["config_version"]
	patch := map[string]any{
		"name": name, "advertised_host": "203.0.113.9", "listen_port": 51840,
		"mtu": 1280, "keepalive_sec": 30, "capacity_mbps": 500,
	}
	resp, patched := s.call(t, http.MethodPatch, path, patch)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH = %d %v, want 200", resp.StatusCode, patched)
	}
	if got, want := patched["config_version"], float64(before.(float64)+1); got != want {
		t.Errorf("config_version после PATCH = %v, want %v", got, want)
	}
	// MTU живёт в [Peer] каждого клиента: не поднять набор — значит оставить у узла
	// прежний MTU. Проверка идёт по вычисленному набору, а не по ответу PATCH.
	uuidID := uuid.MustParse(id)
	set, err := servers.Compute(s.ctx, s.q, uuidID, time.Now())
	if err != nil {
		t.Fatalf("Compute после PATCH: %v", err)
	}
	if set.MTU != 1280 || set.KeepaliveSec != 30 || set.ListenPort != 51840 {
		t.Errorf("desired = mtu %d, keepalive %d, port %d, want 1280/30/51840",
			set.MTU, set.KeepaliveSec, set.ListenPort)
	}

	// draining: набор пустой, и в аудите это server_drained, а не server_updated —
	// оператор должен видеть по логу, что началось вытеснение.
	resp, body := s.call(t, http.MethodPost, path+"/maintenance",
		map[string]string{"status": "draining", "reason": "плановое обслуживание"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("maintenance draining = %d %v", resp.StatusCode, body)
	}
	if body["maintenance_status"] != "draining" {
		t.Errorf("maintenance_status = %v, want draining", body["maintenance_status"])
	}
	set, err = servers.Compute(s.ctx, s.q, uuidID, time.Now())
	if err != nil {
		t.Fatalf("Compute после draining: %v", err)
	}
	if len(set.Peers) != 0 {
		t.Errorf("peers на draining = %d, want 0", len(set.Peers))
	}
	if n := len(auditOf(t, s.ctx, s.q, db.AuditActionServerDrained, id)); n != 1 {
		t.Errorf("записей server_drained = %d, want 1", n)
	}
	// Проверка, что draining действительно снимает пиеров, а не «всегда пустой набор»:
	// на online-сервере с профилем пир обязан появиться.
	user := seedUser(t, s.ctx, s.q, true)
	device := seedDevice(t, s.ctx, s.q, user, 0)
	seedProfile(t, s.ctx, s.q, device.ID, s.server.ID, "10.99.70.3", time.Hour)
	online, err := servers.Compute(s.ctx, s.q, s.server.ID, time.Now())
	if err != nil {
		t.Fatalf("Compute на online: %v", err)
	}
	if len(online.Peers) != 1 {
		t.Fatalf("peers на online с одним профилем = %d, want 1 (иначе проверка draining ничего не доказывает)", len(online.Peers))
	}

	// retired — конец, а не пауза: online из него запрещён.
	resp, body = s.call(t, http.MethodPost, path+"/maintenance",
		map[string]string{"status": "retired", "reason": "сервер выведен из эксплуатации"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("maintenance retired = %d %v", resp.StatusCode, body)
	}
	resp, body = s.call(t, http.MethodPost, path+"/maintenance",
		map[string]string{"status": "online", "reason": "попробовать вернуть в строй"})
	if resp.StatusCode != http.StatusConflict || errorCode(t, body) != "conflict" {
		t.Errorf("retired → online = %d %v, want 409 conflict", resp.StatusCode, body)
	}
	// Неизвестный статус — отказ по полю, а не «записали дефолт».
	if resp, body := s.call(t, http.MethodPost, path+"/maintenance",
		map[string]string{"status": "sleeping", "reason": "проверка границ"}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("неизвестный статус = %d %v, want 400", resp.StatusCode, body)
	}
	// Чужой/несуществующий сервер — 404, а не 500 от пустой строки.
	if resp, body := s.call(t, http.MethodGet, "/api/v1/admin/servers/"+uuid.NewString(), nil); resp.StatusCode != http.StatusNotFound ||
		errorCode(t, body) != "not_found" {
		t.Errorf("несуществующий сервер = %d %v, want 404 not_found", resp.StatusCode, body)
	}
}

// TestAdminDeleteServer: активный профиль блокирует удаление, остаточные — нет, и
// каскад забирает всё служебное, кроме истории событий.
func TestAdminDeleteServer(t *testing.T) {
	s := newAdminStand(t).env(t)
	name := "del-" + uuid.NewString()[:8]
	resp, created := s.call(t, http.MethodPost, "/api/v1/admin/servers",
		newServerBody(name, "dl-"+uuid.NewString()[:8], "10.99.86.0/24", keyFromSeed("del-"+name)))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("создание = %d %v", resp.StatusCode, created)
	}
	id, _ := created["id"].(string)
	serverID := uuid.MustParse(id)
	path := "/api/v1/admin/servers/" + id
	setServerOnline(t, s.ctx, s.q, serverID)

	user := seedUser(t, s.ctx, s.q, true)
	device := seedDevice(t, s.ctx, s.q, user, 0)
	profile := seedProfile(t, s.ctx, s.q, device.ID, serverID, "10.99.86.2", time.Hour)

	// Активный профиль: 409 с настоящим числом — именно его §7.6 обещает админу до
	// подтверждения.
	resp, body := s.call(t, http.MethodDelete, path, nil)
	if resp.StatusCode != http.StatusConflict || errorCode(t, body) != "conflict" {
		t.Fatalf("удаление с активным профилем = %d %v, want 409 conflict", resp.StatusCode, body)
	}
	e, _ := body["error"].(map[string]any)
	details, _ := e["details"].(map[string]any)
	if details["peers_active"] != float64(1) {
		t.Errorf("details.peers_active = %v, want 1", details["peers_active"])
	}
	if _, err := s.q.ServerByID(s.ctx, serverID); err != nil {
		t.Fatalf("сервер обязан пережить отказ: %v", err)
	}
	if p, err := s.q.ProfileByID(s.ctx, profile.ID); err != nil || p.Status != db.ProfileStatusActive {
		t.Fatalf("профиль обязан пережить отказ: %v %+v", err, p)
	}

	// Служебные строки, которые обязан забрать каскад: адрес, health, токен узла,
	// событие с server_id.
	if _, err := pool(t).Exec(s.ctx,
		`INSERT INTO tunnel_addresses (server_id, address, allocated_to) VALUES ($1, $2, $3)`,
		serverID, "10.99.86.2", profile.ID); err != nil {
		t.Fatalf("tunnel_addresses: %v", err)
	}
	if err := s.q.MarkServerHealth(s.ctx, db.MarkServerHealthParams{
		ServerID: serverID, ObservedAt: time.Now(), AppliedConfigVersion: 1,
	}); err != nil {
		t.Fatalf("MarkServerHealth: %v", err)
	}
	raw, _ := insertBootstrap(t, s.ctx, s.q, serverID)
	resp, enrolled := nodeCall(t, http.MethodPost, s.base+"/internal/v1/nodes/enroll",
		mustJSON(t, map[string]string{"bootstrap_token": raw, "public_key": keyFromSeed("del-" + name)}), "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll = %d %v, want 200", resp.StatusCode, enrolled)
	}
	nodeToken, _ := enrolled["node_token"].(string)
	detail, _ := json.Marshal(map[string]any{"reason": "проверка каскада"})
	if err := s.q.InsertConnectionEvent(s.ctx, db.InsertConnectionEventParams{
		UserID: &user, DeviceID: &device.ID, ServerID: &serverID,
		Event: db.EventTypeProfileIssued, Detail: detail,
	}); err != nil {
		t.Fatalf("InsertConnectionEvent: %v", err)
	}
	var eventID int64
	if err := pool(t).QueryRow(s.ctx,
		"SELECT id FROM connection_events WHERE server_id = $1 ORDER BY created_at DESC LIMIT 1", serverID).Scan(&eventID); err != nil {
		t.Fatalf("id события: %v", err)
	}

	// Терминальный остаток (revoked) удаляется вместе с сервером, событий на него не
	// пишется — «отозван» уже не даёт доступа.
	if _, err := s.q.RevokeProfile(s.ctx, profile.ID); err != nil {
		t.Fatalf("RevokeProfile: %v", err)
	}
	resp, body = s.call(t, http.MethodDelete, path, map[string]string{"reason": "сервер выведен и разобран"})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE после отзыва = %d %v, want 204", resp.StatusCode, body)
	}

	for _, q := range []struct {
		sql  string
		what string
	}{
		{"SELECT count(*) FROM vpn_servers WHERE id = $1", "vpn_servers"},
		{"SELECT count(*) FROM tunnel_addresses WHERE server_id = $1", "tunnel_addresses"},
		{"SELECT count(*) FROM server_health WHERE server_id = $1", "server_health"},
		{"SELECT count(*) FROM node_credentials WHERE server_id = $1", "node_credentials"},
		{"SELECT count(*) FROM bootstrap_tokens WHERE server_id = $1", "bootstrap_tokens"},
		{"SELECT count(*) FROM vpn_profiles WHERE server_id = $1", "vpn_profiles"},
	} {
		if n := countQuery(t, s.ctx, q.sql, serverID); n != 0 {
			t.Errorf("%s после удаления сервера = %d, want 0", q.what, n)
		}
	}
	// История событий принадлежит пользователям и устройствам, а не серверу: строка
	// остаётся с server_id = null.
	var kept uuid.NullUUID
	if err := pool(t).QueryRow(s.ctx,
		"SELECT server_id FROM connection_events WHERE id = $1", eventID).Scan(&kept); err != nil {
		t.Fatalf("событие после удаления сервера исчезло: %v", err)
	}
	if kept.Valid {
		t.Errorf("connection_events.server_id = %v, want NULL", kept.UUID)
	}
	// Старый токен узла после каскада не имеет права ничего открыть.
	if resp, _ := nodeCall(t, http.MethodGet, s.base+"/internal/v1/nodes/"+serverID.String()+"/desired",
		"", nodeToken, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("desired старым токеном удалённого узла = %d, want 401", resp.StatusCode)
	}
	rows := auditOf(t, s.ctx, s.q, db.AuditActionServerDeleted, id)
	if len(rows) != 1 || rows[0].Reason == "" {
		t.Fatalf("запись server_deleted с причиной: %+v", rows)
	}
}

func TestAdminBootstrapTokens(t *testing.T) {
	s := newAdminStand(t).env(t)
	name := "boot-" + uuid.NewString()[:8]
	resp, created := s.call(t, http.MethodPost, "/api/v1/admin/servers",
		newServerBody(name, "bt-"+uuid.NewString()[:8], "10.99.87.0/24", keyFromSeed("boot-"+name)))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("создание сервера = %d %v", resp.StatusCode, created)
	}
	id, _ := created["id"].(string)
	serverID := uuid.MustParse(id)
	path := "/api/v1/admin/servers/" + id

	resp, body := s.call(t, http.MethodPost, path+"/bootstrap-tokens", map[string]any{})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST bootstrap-tokens = %d %v, want 201", resp.StatusCode, body)
	}
	raw, _ := body["token"].(string)
	if !nodeTokenShape.MatchString(raw) {
		t.Errorf("токен %q не соответствует форме узлового секрета", raw)
	}
	tokID, _ := body["id"].(string)
	expires, _ := body["expires_at"].(string)
	at, err := time.Parse(time.RFC3339, expires)
	if err != nil {
		t.Fatalf("expires_at %q: %v", expires, err)
	}
	if d := time.Until(at); d < 55*time.Minute || d > 61*time.Minute {
		t.Errorf("expires_at через %v, want ≈ 1 час (ttl по умолчанию 3600)", d)
	}
	// В базе — только sha256: восстановить выданный секрет нельзя по построению.
	sum := sha256.Sum256([]byte(raw))
	var hash []byte
	if err := pool(t).QueryRow(s.ctx, "SELECT token_hash FROM bootstrap_tokens WHERE id = $1", uuid.MustParse(tokID)).Scan(&hash); err != nil {
		t.Fatalf("строка токена: %v", err)
	}
	if !bytes.Equal(hash, sum[:]) {
		t.Errorf("token_hash = %x, want sha256 от выданного значения", hash)
	}
	// Enroll этим токеном (маршрут задачи 11) обязан пройти: admin выдаёт токен,
	// который узел действительно может потратить.
	resp, enrolled := nodeCall(t, http.MethodPost, s.base+"/internal/v1/nodes/enroll",
		mustJSON(t, map[string]string{"bootstrap_token": raw, "public_key": keyFromSeed("boot-" + name)}), "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll токеном админа = %d %v, want 200", resp.StatusCode, enrolled)
	}

	// Границы ttl_sec: окно 60..86400, оба края за пределом — 400 по полю ttl_sec.
	for _, ttl := range []int{30, 100000} {
		resp, body = s.call(t, http.MethodPost, path+"/bootstrap-tokens", map[string]int{"ttl_sec": ttl})
		if resp.StatusCode != http.StatusBadRequest || errorCode(t, body) != "invalid_request" {
			t.Errorf("ttl_sec=%d → %d %v, want 400 invalid_request", ttl, resp.StatusCode, body)
		}
		if f := envelopeDetailsField(t, body); f != "ttl_sec" {
			t.Errorf("ttl_sec=%d: details.field = %q, want ttl_sec", ttl, f)
		}
	}
	// Край окна принимается: граница 60 — не «чуть больше», а ровно 60. Второй токен
	// заводится отдельно и не тратится: первый уже сожжён enroll'ом, и отзыв
	// сожжённого не доказал бы, что отзыв живого что-то меняет.
	resp, short := s.call(t, http.MethodPost, path+"/bootstrap-tokens", map[string]int{"ttl_sec": 60})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("ttl_sec=60 → %d %v, want 201", resp.StatusCode, short)
	}
	shortRaw, _ := short["token"].(string)
	shortID, _ := short["id"].(string)
	if shortRaw == "" || shortID == "" {
		t.Fatalf("в ответе ttl_sec=60 нет token или id: %v", short)
	}

	// Список: id и сроки, без секрета и без хэша.
	resp, body = s.call(t, http.MethodGet, path+"/bootstrap-tokens", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET bootstrap-tokens = %d %v", resp.StatusCode, body)
	}
	for _, row := range jsonArray(t, body, "bootstrap_tokens") {
		for _, banned := range []string{"token", "token_hash"} {
			if _, ok := row[banned]; ok {
				t.Errorf("строка списка содержит %q: %v", banned, row)
			}
		}
	}

	// Отзыв живого токена: 204 — изменение есть, показывать нечего.
	resp, body = s.call(t, http.MethodDelete, "/api/v1/admin/bootstrap-tokens/"+shortID,
		map[string]string{"reason": "токен больше не нужен"})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("первый отзыв = %d %v, want 204", resp.StatusCode, body)
	}
	// Непотраченный токен после отзыва не enroll'ится. Здесь обязана быть именно
	// короткая строка: с raw из начала теста 401 вернулся бы и без отзыва.
	if resp, _ := nodeCall(t, http.MethodPost, s.base+"/internal/v1/nodes/enroll",
		mustJSON(t, map[string]string{"bootstrap_token": shortRaw, "public_key": keyFromSeed("boot-" + name)}), "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("enroll отозванным токеном = %d, want 401", resp.StatusCode)
	}
	// Повторный отзыв — 409, а не молчаливое 204: «отозвал то, чего уже нет» оператор
	// обязан увидеть.
	resp, body = s.call(t, http.MethodDelete, "/api/v1/admin/bootstrap-tokens/"+shortID,
		map[string]string{"reason": "повторный отзыв того же токена"})
	if resp.StatusCode != http.StatusConflict || errorCode(t, body) != "conflict" {
		t.Errorf("второй отзыв = %d %v, want 409 conflict", resp.StatusCode, body)
	}

	// Сервер в retired: токен выдавать бессмысленно — 409; несуществующий сервер — 404.
	if _, err := s.q.SetServerMaintenance(s.ctx, db.SetServerMaintenanceParams{
		ID: serverID, MaintenanceStatus: db.MaintenanceStatusRetired,
	}); err != nil {
		t.Fatalf("retired: %v", err)
	}
	resp, body = s.call(t, http.MethodPost, path+"/bootstrap-tokens", map[string]any{})
	if resp.StatusCode != http.StatusConflict || errorCode(t, body) != "conflict" {
		t.Errorf("токен для retired = %d %v, want 409 conflict", resp.StatusCode, body)
	}
	if resp, body := s.call(t, http.MethodPost, "/api/v1/admin/servers/"+uuid.NewString()+"/bootstrap-tokens", map[string]any{}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("токен для несуществующего сервера = %d %v, want 404", resp.StatusCode, body)
	}
	if n := len(auditOf(t, s.ctx, s.q, db.AuditActionBootstrapTokenIssued, "")); n == 0 {
		t.Error("в аудите нет ни одной записи bootstrap_token_issued")
	}
}

func TestAdminNodeTokenRevoke(t *testing.T) {
	s := newAdminStand(t).env(t)
	serverID := s.server.ID
	raw, _ := insertBootstrap(t, s.ctx, s.q, serverID)
	resp, enrolled := nodeCall(t, http.MethodPost, s.base+"/internal/v1/nodes/enroll",
		mustJSON(t, map[string]string{"bootstrap_token": raw, "public_key": s.server.PublicKey}), "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll = %d %v", resp.StatusCode, enrolled)
	}
	nodeToken, _ := enrolled["node_token"].(string)

	reason := "узел скомпрометирован"
	resp, body := s.call(t, http.MethodPost, "/api/v1/admin/servers/"+serverID.String()+"/node-token/revoke",
		map[string]string{"reason": reason})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("node-token/revoke = %d %v, want 204", resp.StatusCode, body)
	}
	// Предъявленный узлом токен больше не пускает.
	if resp, _ := nodeCall(t, http.MethodGet, s.base+"/internal/v1/nodes/"+serverID.String()+"/desired",
		"", nodeToken, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("desired отозванным токеном = %d, want 401", resp.StatusCode)
	}
	// И узел выведен из раздачи: «отрезан» означает, что новых пиеров не набирают.
	srv, err := s.q.ServerByID(s.ctx, serverID)
	if err != nil {
		t.Fatalf("ServerByID: %v", err)
	}
	if srv.MaintenanceStatus != db.MaintenanceStatusDraining {
		t.Errorf("maintenance_status = %v, want draining", srv.MaintenanceStatus)
	}
	// Две записи одного решения: node_token_revoked и server_drained с тем же
	// request_id — «узел отрезан» и «набор снят» читаются как один шаг.
	revoked := auditOf(t, s.ctx, s.q, db.AuditActionNodeTokenRevoked, serverID.String())
	drained := auditOf(t, s.ctx, s.q, db.AuditActionServerDrained, serverID.String())
	if len(revoked) != 1 || len(drained) != 1 {
		t.Fatalf("записи аудита: revoked %d, drained %d, want 1 и 1", len(revoked), len(drained))
	}
	if revoked[0].RequestID != drained[0].RequestID {
		t.Errorf("request_id разные: %q и %q — одно решение должно читаться одним шагом",
			revoked[0].RequestID, drained[0].RequestID)
	}
	if revoked[0].Reason != reason || drained[0].Reason != reason {
		t.Errorf("причина потеряна: %q / %q", revoked[0].Reason, drained[0].Reason)
	}
	if id := requestID(t, resp); id != revoked[0].RequestID {
		t.Errorf("request_id в аудите %q не совпадает с заголовком ответа %q", revoked[0].RequestID, id)
	}
	// Повтор на сервере без живых токенов — не ошибка: отзывов нет у ещё не
	// зарегистрированного узла.
	if resp, body := s.call(t, http.MethodPost, "/api/v1/admin/servers/"+serverID.String()+"/node-token/revoke",
		map[string]string{"reason": "повторный отзыв того же узла"}); resp.StatusCode != http.StatusNoContent {
		t.Errorf("повторный revoke = %d %v, want 204", resp.StatusCode, body)
	}
}

// TestAdminLockUser: блокировка снимает доступ целиком — профили, адреса, refresh,
// desired set, — и оставляет след с причиной и request_id.
func TestAdminLockUser(t *testing.T) {
	s := newAdminStand(t).env(t)
	email := "lock-" + uuid.NewString()[:8] + "@novavpn.test"
	resp, reg := do(t, http.MethodPost, s.base+"/api/v1/auth/register",
		map[string]string{"email": email, "password": testPassword}, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register = %d %v", resp.StatusCode, reg)
	}
	refresh, _ := reg["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("в ответе регистрации нет refresh_token: %v", reg)
	}
	// id читается из базы, а не из ответа: сессия наружу отдаёт токены, и тест,
	// выманивающий user_id из ответа, требовал бы от API лишнего поля.
	created, err := s.q.UserByEmail(s.ctx, email)
	if err != nil {
		t.Fatalf("UserByEmail после регистрации: %v", err)
	}
	userID := created.ID
	device := seedDevice(t, s.ctx, s.q, userID, 0)
	profile := seedProfile(t, s.ctx, s.q, device.ID, s.server.ID, "10.99.70.4", time.Hour)
	if _, err := pool(t).Exec(s.ctx,
		`INSERT INTO tunnel_addresses (server_id, address, allocated_to) VALUES ($1, $2, $3)`,
		s.server.ID, "10.99.70.4", profile.ID); err != nil {
		t.Fatalf("tunnel_addresses: %v", err)
	}
	// Версия читается непосредственно перед блокировкой: s.server заморожен на
	// моменте newAdminStand, а setServerOnline и seedProfile уже поднимали её.
	before, err := s.q.ServerByID(s.ctx, s.server.ID)
	if err != nil {
		t.Fatalf("ServerByID перед блокировкой: %v", err)
	}
	versionBefore := before.ConfigVersion

	path := "/api/v1/admin/users/" + userID.String()
	reason := "множественные нарушения правил сервиса"
	lockResp, body := s.call(t, http.MethodPost, path+"/lock", map[string]string{"reason": reason})
	if lockResp.StatusCode != http.StatusOK {
		t.Fatalf("lock = %d %v, want 200", lockResp.StatusCode, body)
	}

	// Профиль отозван, адрес освобождён, версия поднята, событие на каждый профиль.
	p, err := s.q.ProfileByID(s.ctx, profile.ID)
	if err != nil {
		t.Fatalf("ProfileByID: %v", err)
	}
	if p.Status != db.ProfileStatusRevoked || p.RevokedAt == nil {
		t.Errorf("профиль после блокировки = %v (revoked_at %v), want revoked", p.Status, p.RevokedAt)
	}
	var allocatedTo *uuid.UUID
	if err := pool(t).QueryRow(s.ctx,
		"SELECT allocated_to FROM tunnel_addresses WHERE server_id = $1 AND address = $2",
		s.server.ID, "10.99.70.4").Scan(&allocatedTo); err != nil {
		t.Fatalf("чтение адреса: %v", err)
	}
	if allocatedTo != nil {
		t.Errorf("адрес остался занят: %v", allocatedTo)
	}
	srv, err := s.q.ServerByID(s.ctx, s.server.ID)
	if err != nil {
		t.Fatalf("ServerByID: %v", err)
	}
	if srv.ConfigVersion != versionBefore+1 {
		t.Errorf("config_version = %d, want %d", srv.ConfigVersion, versionBefore+1)
	}
	set, err := servers.Compute(s.ctx, s.q, s.server.ID, time.Now())
	if err != nil {
		t.Fatalf("Compute после блокировки: %v", err)
	}
	if len(set.Peers) != 0 {
		t.Errorf("peers после блокировки = %d, want 0 — «заблокировали, а пиер живёт» недопустимо", len(set.Peers))
	}
	if n := countQuery(t, s.ctx,
		`SELECT count(*) FROM connection_events WHERE device_id = $1 AND event = 'profile_revoked'
		   AND detail->>'reason' = 'user_locked'`, device.ID); n != 1 {
		t.Errorf("событий profile_revoked с причиной user_locked = %d, want 1", n)
	}

	// Refresh-семьи отзованы: продлиться нельзя. Текущий access доживает TTL — это
	// ограничение A-1, оно записано в §13 и здесь не прячется.
	resp, body = do(t, http.MethodPost, s.base+"/api/v1/auth/refresh",
		map[string]string{"refresh_token": refresh}, "")
	if resp.StatusCode != http.StatusUnauthorized || errorCode(t, body) != "refresh_token_invalid" {
		t.Errorf("refresh после блокировки = %d %v, want 401 refresh_token_invalid", resp.StatusCode, body)
	}

	rows := auditOf(t, s.ctx, s.q, db.AuditActionUserLocked, userID.String())
	if len(rows) != 1 {
		t.Fatalf("записей user_locked = %d, want 1", len(rows))
	}
	if rows[0].Reason != reason {
		t.Errorf("причина в аудите = %q, want %q", rows[0].Reason, reason)
	}
	// request_id аудита — заголовок именно lock-ответа: по нему оператор связывает
	// строку журнала с записью в базе. Первый же refresh этот заголовок перезаписал бы.
	id := requestID(t, lockResp)
	if rows[0].RequestID != id {
		t.Errorf("request_id в аудите %q, в заголовке lock-ответа %q", rows[0].RequestID, id)
	}
	if !strings.Contains(s.logs.String(), `"request_id":"`+id+`"`) {
		t.Errorf("request_id %q не встречается в журнале ни в одной строке", id)
	}

	// Повторная блокировка — 409: второй вызов молча перезаписал бы причину, и она
	// исчезла бы из единственного места, где её видно.
	resp, body = s.call(t, http.MethodPost, path+"/lock", map[string]string{"reason": "вторая причина блокировки"})
	if resp.StatusCode != http.StatusConflict || errorCode(t, body) != "conflict" {
		t.Errorf("второй lock = %d %v, want 409 conflict", resp.StatusCode, body)
	}
	// Разблокировка: право войти возвращается, выданные конфиги — нет.
	resp, body = s.call(t, http.MethodPost, path+"/unlock", map[string]string{"reason": "ошибка оператора исправлена"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unlock = %d %v, want 200", resp.StatusCode, body)
	}
	resp, body = s.call(t, http.MethodPost, path+"/unlock", map[string]string{"reason": "повторная разблокировка"})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("unlock активного = %d %v, want 409", resp.StatusCode, body)
	}
	if err := s.q.UnlockUser(s.ctx, userID); err != nil {
		t.Fatalf("UnlockUser для следующего шага: %v", err)
	}
	resp, body = do(t, http.MethodPost, s.base+"/api/v1/auth/login",
		map[string]string{"email": email, "password": testPassword}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("вход разблокированного = %d %v, want 200", resp.StatusCode, body)
	}
	userToken, _ := body["access_token"].(string)
	resp, body = do(t, http.MethodGet, s.base+"/api/v1/devices/"+device.ID.String()+"/profiles", nil, userToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("список профилей = %d %v", resp.StatusCode, body)
	}
	// Список отдаёт и терминальные профили (A-1: человек имеет право видеть, что
	// с его доступом случилось), поэтому проверяется отсутствие живых, а не пустота:
	// разблокировка возвращает право войти, а не прежние конфиги.
	items := jsonArray(t, body, "profiles")
	for _, item := range items {
		if status, _ := item["status"].(string); status == "active" || status == "superseded" {
			t.Errorf("профиль %v после разблокировки в статусе %q, want только терминальный", item["id"], status)
		}
	}
	if len(items) == 0 {
		t.Error("отозванный профиль не показан: человеку нечем увидеть, что с доступом случилось")
	}
	if n := len(auditOf(t, s.ctx, s.q, db.AuditActionUserUnlocked, userID.String())); n != 1 {
		t.Errorf("записей user_unlocked = %d, want 1", n)
	}
	// Повторная блокировка после unlock обязана пройти: 409 относится к уже
	// заблокированному, а не к «этого пользователя когда-либо блокировали».
	if resp, body := s.call(t, http.MethodPost, path+"/lock", map[string]string{"reason": "нарушения возобновились"}); resp.StatusCode != http.StatusOK {
		t.Errorf("lock после unlock = %d %v, want 200", resp.StatusCode, body)
	}
}

// TestAdminLockInvalidReasonAndMissingUser: причина проверяется до любого изменения,
// поэтому «400 по причине» обязан не оставить ни одного следа.
func TestAdminLockInvalidReasonAndMissingUser(t *testing.T) {
	s := newAdminStand(t).env(t)
	user := seedUser(t, s.ctx, s.q, true)
	path := "/api/v1/admin/users/" + user.String()
	auditBefore := countQuery(t, s.ctx, "SELECT count(*) FROM admin_audit_logs")

	for _, reason := range []string{"да", strings.Repeat("п", 501)} {
		resp, body := s.call(t, http.MethodPost, path+"/lock", map[string]string{"reason": reason})
		if resp.StatusCode != http.StatusBadRequest || errorCode(t, body) != "invalid_request" {
			t.Fatalf("причина из %d символов → %d %v, want 400 invalid_request", len(reason), resp.StatusCode, body)
		}
		if f := envelopeDetailsField(t, body); f != "reason" {
			t.Errorf("details.field = %q, want reason", f)
		}
	}
	// Причина обязательна: без поля — тот же отказ по тому же полю.
	if resp, body := s.call(t, http.MethodPost, path+"/lock", map[string]string{}); resp.StatusCode != http.StatusBadRequest ||
		envelopeDetailsField(t, body) != "reason" {
		t.Errorf("lock без причины = %d %v, want 400 field=reason", resp.StatusCode, body)
	}
	if row, err := s.q.UserByID(s.ctx, user); err != nil || row.Status != db.UserStatusActive {
		t.Errorf("пользователь изменён: %+v (%v)", row, err)
	}
	if n := countQuery(t, s.ctx, "SELECT count(*) FROM admin_audit_logs"); n != auditBefore {
		t.Errorf("записей аудита стало %d, было %d — отказ по причине оставил след", n, auditBefore)
	}
	// Три кириллических символа — 6 байт: счёт в символах, а не в байтах.
	if resp, body := s.call(t, http.MethodPost, path+"/lock", map[string]string{"reason": "давай"}); resp.StatusCode != http.StatusOK {
		t.Errorf("причина из 3 кириллических символов = %d %v, want 200", resp.StatusCode, body)
	}
	// Несуществующий пользователь — 404, а не 500 от пустой строки.
	if resp, body := s.call(t, http.MethodPost, "/api/v1/admin/users/"+uuid.NewString()+"/lock",
		map[string]string{"reason": "проверка 404"}); resp.StatusCode != http.StatusNotFound || errorCode(t, body) != "not_found" {
		t.Errorf("lock несуществующего = %d %v, want 404 not_found", resp.StatusCode, body)
	}
}

func TestAdminUserViewAndCreateAdminAndAuditBounds(t *testing.T) {
	s := newAdminStand(t).env(t)
	user := seedUser(t, s.ctx, s.q, true)
	device := seedDevice(t, s.ctx, s.q, user, 0)
	if _, err := pool(t).Exec(s.ctx,
		`INSERT INTO device_day_traffic (user_id, device_id, day, rx_bytes, tx_bytes)
		 VALUES ($1, $2, current_date, 1000, 2000)`, user, device.ID); err != nil {
		t.Fatalf("device_day_traffic: %v", err)
	}

	resp, body := s.call(t, http.MethodGet, "/api/v1/admin/users/"+user.String(), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /users/{id} = %d %v, want 200", resp.StatusCode, body)
	}
	// Хэша нет ни в запросе, ни в типе ответа — проверяется по байтам ответа:
	// «мы просто не показали поле» не доказывает, что оно не ушло клиенту.
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal ответа: %v", err)
	}
	for _, banned := range []string{"password_hash", "argon2id"} {
		if strings.Contains(string(raw), banned) {
			t.Errorf("ответ пользователя содержит %q: %s", banned, raw)
		}
	}
	// Тот же тест по журналу: id есть, хэша и email нет.
	line := journalLineFor(t, s.logs.String(), "GET /api/v1/admin/users/{id}")
	if line == nil {
		t.Fatalf("в журнале нет строки запроса пользователя")
	}
	if got, _ := line["admin_id"].(string); got != s.admin.String() {
		t.Errorf("admin_id = %q, want %q", got, s.admin.String())
	}
	if _, ok := line["user_id"]; ok {
		t.Error("user_id на admin-маршруте: субъекты обязаны различаться")
	}
	for k := range line {
		if strings.Contains(k, "email") {
			t.Errorf("журнал содержит поле %q: личности там, где есть id, запрещены §10/§15", k)
		}
	}
	if devices := jsonArray(t, body, "devices"); len(devices) != 1 {
		t.Errorf("devices = %v, want одна живая строка", devices)
	}
	traffic := jsonArray(t, body, "traffic")
	if len(traffic) != 1 {
		t.Fatalf("traffic = %v, want агрегат за окно", traffic)
	}
	if traffic[0]["rx_bytes"] != float64(1000) || traffic[0]["tx_bytes"] != float64(2000) {
		t.Errorf("traffic = %v, want 1000/2000", traffic[0])
	}
	if traffic[0]["days"] != float64(1) {
		t.Errorf("days = %v, want 1", traffic[0]["days"])
	}

	// Создание админа: короткий пароль — 400 и ни одной новой строки; дубликат
	// email — 409 (email_taken закреплён контрактом за регистрацией участников).
	countBefore := countQuery(t, s.ctx, "SELECT count(*) FROM admin_users")
	resp, body = s.call(t, http.MethodPost, "/api/v1/admin/admins",
		map[string]string{"email": "short-" + uuid.NewString()[:8] + "@novavpn.test", "password": "short"})
	if resp.StatusCode != http.StatusBadRequest || errorCode(t, body) != "invalid_request" {
		t.Errorf("короткий пароль = %d %v, want 400 invalid_request", resp.StatusCode, body)
	}
	if n := countQuery(t, s.ctx, "SELECT count(*) FROM admin_users"); n != countBefore {
		t.Errorf("админов стало %d, было %d", n, countBefore)
	}
	resp, body = s.call(t, http.MethodPost, "/api/v1/admin/admins",
		map[string]string{"email": s.email, "password": "another-admin-password-1"})
	if resp.StatusCode != http.StatusConflict || errorCode(t, body) != "conflict" {
		t.Errorf("дубликат email = %d %v, want 409 conflict", resp.StatusCode, body)
	}
	newEmail := "fresh-" + uuid.NewString()[:8] + "@novavpn.test"
	resp, body = s.call(t, http.MethodPost, "/api/v1/admin/admins",
		map[string]string{"email": newEmail, "password": "another-admin-password-1"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("новый админ = %d %v, want 201", resp.StatusCode, body)
	}
	if n := len(auditOf(t, s.ctx, s.q, db.AuditActionAdminCreated, "")); n == 0 {
		t.Error("в аудите нет записи admin_created")
	}
	// Созданный админ входит: пароль и email реально записаны, а не «201 в никуда».
	if tok := loginAdmin(t, s.base, newEmail, "another-admin-password-1"); tok == "" {
		t.Error("вход созданного админа не выдал токена")
	}

	// Границы аудита: limit 1..500, offset 0..10000.
	for _, q := range []string{"limit=0", "limit=501", "offset=10001", "limit=abc", "offset=-1"} {
		resp, body = s.call(t, http.MethodGet, "/api/v1/admin/audit?"+q, nil)
		if resp.StatusCode != http.StatusBadRequest || errorCode(t, body) != "invalid_request" {
			t.Errorf("аудит %s → %d %v, want 400 invalid_request", q, resp.StatusCode, body)
		}
	}
	resp, body = s.call(t, http.MethodGet, "/api/v1/admin/audit?limit=5&offset=0", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /audit = %d %v", resp.StatusCode, body)
	}
	rows := jsonArray(t, body, "audit")
	if len(rows) == 0 {
		t.Fatal("аудит пуст, хотя действия уже выполнялись")
	}
	if len(rows) > 5 {
		t.Errorf("строк %d, want не больше limit=5", len(rows))
	}
	// Порядок читается из created_at ответа, а не из базы: админ видит именно то,
	// что ему отдали.
	stamp := func(row map[string]any) time.Time {
		raw, ok := row["created_at"].(string)
		if !ok {
			t.Fatalf("в строке аудита нет created_at: %v", row)
		}
		at, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			t.Fatalf("created_at %q не разбирается: %v", raw, err)
		}
		return at
	}
	for i := 1; i < len(rows); i++ {
		if stamp(rows[i-1]).Before(stamp(rows[i])) {
			t.Errorf("строки не упорядочены по created_at DESC: %s раньше %s",
				rows[i-1]["created_at"], rows[i]["created_at"])
		}
	}
	for _, row := range rows {
		if reason, _ := row["reason"].(string); reason == "" {
			t.Errorf("запись аудита без причины: %v", row)
		}
		if id, _ := row["request_id"].(string); id == "" {
			t.Errorf("запись аудита без request_id: %v", row)
		}
	}
}

// journalLineFor — строка журнала запроса по шаблону маршрута. Возвращается карта
// полей, чтобы тест называл поле, а не подстроку.
func journalLineFor(t *testing.T, logs, route string) map[string]any {
	t.Helper()
	lines := requestLines(t, logs)
	if entry, ok := lines[route]; ok {
		return entry
	}
	return nil
}

// TestAdminAuditDoValidatesBeforeTransaction: валидация причины происходит до
// начала транзакции, а не «после, и тогда откат».
func TestAdminAuditDoValidatesBeforeTransaction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := db.New(pool(t))
	// admin_id в ссылке на существующего администратора: с выдуманным uuid положительный
	// контроль падал бы по внешнему ключу, и «отказ по причине» нельзя было бы
	// отличить от «отказ по данным».
	adminID, _ := seedAdmin(t, ctx, q)
	city := "audit-" + uuid.NewString()[:8]
	mutated := 0
	err := audit.Do(ctx, pool(t), audit.Action{
		AdminID: adminID, Action: db.AuditActionServerCreated,
		TargetType: "server", TargetID: uuid.NewString(),
		Reason: "да", RequestID: "0000000000000001",
	}, func(tx *db.Queries) error {
		mutated++
		_, err := tx.InsertServerLocation(ctx, db.InsertServerLocationParams{
			ID: uuid.New(), CountryCode: "DE", City: city,
			Lat: "52.5200", Lon: "13.4050", Timezone: "Europe/Berlin",
		})
		return err
	})
	if err == nil {
		t.Fatal("причина из двух символов принята")
	}
	if mutated != 0 {
		t.Errorf("mutate вызвана %d раз, want 0: отказ должен случиться до транзакции", mutated)
	}
	if n := countQuery(t, ctx, "SELECT count(*) FROM server_locations WHERE city = $1", city); n != 0 {
		t.Errorf("локаций %s = %d, want 0", city, n)
	}
	// Положительный контроль: корректная причина пишет и изменение, и след.
	good := uuid.New()
	if err := audit.Do(ctx, pool(t), audit.Action{
		AdminID: adminID, Action: db.AuditActionServerCreated,
		TargetType: "location", TargetID: good.String(),
		Reason: "проверка положительного пути", RequestID: "0000000000000002",
	}, func(tx *db.Queries) error {
		_, err := tx.InsertServerLocation(ctx, db.InsertServerLocationParams{
			ID: good, CountryCode: "DE", City: city,
			Lat: "52.5200", Lon: "13.4050", Timezone: "Europe/Berlin",
		})
		return err
	}); err != nil {
		t.Fatalf("корректное действие отклонено: %v", err)
	}
	if n := countQuery(t, ctx, "SELECT count(*) FROM server_locations WHERE city = $1", city); n != 1 {
		t.Errorf("локаций после корректного действия = %d, want 1", n)
	}
	if n := len(auditOf(t, ctx, q, db.AuditActionServerCreated, good.String())); n != 1 {
		t.Errorf("записей аудита = %d, want 1", n)
	}
}

// TestAdminJournalCarriesNoSecrets: ни email, ни bootstrap-секрет, ни пароль не
// имеют права попасть в журнал запросов.
func TestAdminJournalCarriesNoSecrets(t *testing.T) {
	s := newAdminStand(t).env(t)
	resp, created := s.call(t, http.MethodPost, "/api/v1/admin/servers",
		newServerBody("sec-"+uuid.NewString()[:8], "sc-"+uuid.NewString()[:8], "10.99.88.0/24",
			keyFromSeed("sec-"+uuid.NewString())))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("создание сервера = %d %v", resp.StatusCode, created)
	}
	id, _ := created["id"].(string)
	resp, body := s.call(t, http.MethodPost, "/api/v1/admin/servers/"+id+"/bootstrap-tokens", map[string]any{})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("bootstrap-токен = %d %v", resp.StatusCode, body)
	}
	raw, _ := body["token"].(string)
	if raw == "" {
		t.Fatal("в ответе нет токена")
	}

	logs := s.logs.String()
	if strings.Contains(logs, raw) {
		t.Error("журнал содержит bootstrap-токен")
	}
	if strings.Contains(logs, adminPassword) {
		t.Error("журнал содержит пароль админа")
	}
	if strings.Contains(logs, s.email) {
		t.Errorf("журнал содержит email админа %s", s.email)
	}
	// Положительный контроль: admin_id в журнале есть, и это единственное, чем
	// админский запрос отличим от анонимного.
	if !strings.Contains(logs, `"admin_id":"`+s.admin.String()+`"`) {
		t.Errorf("в журнале нет admin_id %s: сопоставить строку с аудитом нечем", s.admin)
	}
	if n := journalReasons(t, logs, "unknown_email"); n != 0 {
		t.Errorf("журнал содержит причину отказа несуществующего входа (%d), want 0", n)
	}
}
