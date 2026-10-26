//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/connections"
	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/entitlements"
	"github.com/novavpn/novavpn/internal/httpx"
)

// profilesHTTP собирает те же маршруты, что и сборщик, но с passthrough-обёртками:
// здесь проверяются маршрутизация, коды и порядок собственных обёрток модуля, а
// аутентификация и настоящий лимитер — предметы matrix_test и ratelimit_test.
func profilesHTTP(t *testing.T, idem *httpx.Idempotency, limit func(http.Handler) http.Handler) http.Handler {
	t.Helper()
	p := pool(t)
	svc := connections.NewService(p, entitlements.New(db.New(p)))
	passthrough := func(next http.Handler) http.Handler { return next }
	dec := httpx.Decorators{Auth: passthrough, Anonymous: passthrough}
	mux := http.NewServeMux()
	connections.NewHandler(svc, idem, limit).RegisterRoutes(mux, dec)
	return mux
}

func call(h http.Handler, user uuid.UUID, method, path, body, key string) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	req = req.Clone(httpx.WithUserID(req.Context(), user))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

type errEnvelope struct {
	Error struct {
		Code    string         `json:"code"`
		Message string         `json:"message"`
		Details map[string]any `json:"details"`
	} `json:"error"`
}

func decodeErr(t *testing.T, w *httptest.ResponseRecorder) errEnvelope {
	t.Helper()
	var e errEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("тело не является конвертом ошибки: %v — %s", err, w.Body)
	}
	return e
}

func decodeProfile(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("тело не является профилем: %v — %s", err, w.Body)
	}
	return v
}

// issueViaHTTP выдаёт профиль через маршруты. Пустой key означает «заголовка нет» и
// не подменяется сгенерированным: отсутствие ключа — проверяемый случай, а не
// удобство вызывающего кода.
func issueViaHTTP(t *testing.T, h http.Handler, user, device, server uuid.UUID, key string) *httptest.ResponseRecorder {
	t.Helper()
	return call(h, user, http.MethodPost, "/api/v1/devices/"+device.String()+"/profiles",
		fmt.Sprintf(`{"server_id":%q}`, server.String()), key)
}

func TestProfilesHTTPIssueReplayAndConflicts(t *testing.T) {
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	srv := seedServer(t, ctx, q, "10.96.50.0/29")
	setServerOnline(t, ctx, q, srv.ID)
	user := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, user, 0).ID
	h := profilesHTTP(t, httpx.NewIdempotency(httpx.NewPGIdempotency(p)), nil)

	// Без ключа — отказ до всякой идемпотентности: требование проверяется самим
	// модулем, а не обёрткой, иначе тест с nil-хранилищем проходил бы молча.
	w := issueViaHTTP(t, h, user, device, srv.ID, "")
	noKey := decodeErr(t, w)
	// Сообщение проверяется вместе с кодом: обёртка идемпотентности отказывает на тот
	// же код по-английски, и по одному коду нельзя отличить «требование проверил
	// модуль до обёртки» от «это ответила сама обёртка».
	if w.Code != http.StatusBadRequest || noKey.Error.Code != "idempotency_key_required" ||
		!strings.Contains(noKey.Error.Message, "обязателен") {
		t.Fatalf("выдача без ключа: %d %s", w.Code, w.Body)
	}

	// Плохой server_id в теле — 400 с названием поля: 404 на опечатку клиента
	// прятал бы причину.
	w = call(h, user, http.MethodPost, "/api/v1/devices/"+device.String()+"/profiles",
		`{"server_id":"not-a-uuid"}`, uuid.NewString())
	e := decodeErr(t, w)
	if w.Code != http.StatusBadRequest || e.Error.Code != "invalid_request" ||
		e.Error.Details["field"] != "server_id" {
		t.Fatalf("плохой server_id: %d %s", w.Code, w.Body)
	}

	key := uuid.NewString()
	w = issueViaHTTP(t, h, user, device, srv.ID, key)
	if w.Code != http.StatusCreated {
		t.Fatalf("выдача = %d %s", w.Code, w.Body)
	}
	view := decodeProfile(t, w)
	for _, field := range []string{"id", "device_id", "server_id", "address_v4", "status",
		"issued_at", "expires_at"} {
		if _, ok := view[field]; !ok {
			t.Errorf("в ответе нет поля %q: %s", field, w.Body)
		}
	}
	if view["status"] != "active" {
		t.Errorf("status = %v, want active", view["status"])
	}
	if view["overlap_valid_until"] != nil || view["revoked_at"] != nil {
		t.Errorf("у новой выдачи окна и отзыва быть не должно: %s", w.Body)
	}

	// Тот же ключ и то же тело — повтор первого результата, а не вторая выдача.
	replayed := issueViaHTTP(t, h, user, device, srv.ID, key)
	if replayed.Code != http.StatusCreated ||
		replayed.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("повтор с тем же ключом: %d replayed=%q %s",
			replayed.Code, replayed.Header().Get("Idempotency-Replayed"), replayed.Body)
	}
	if decodeProfile(t, replayed)["id"] != view["id"] {
		t.Error("повтор вернул другой профиль вместо сохранённого результата")
	}
	// Повтор не должен оставить второй адрес: проверка на уровне базы, а не ответа.
	var rows int
	if err := p.QueryRow(ctx,
		"SELECT count(*) FROM tunnel_addresses WHERE server_id = $1", srv.ID).Scan(&rows); err != nil {
		t.Fatalf("count адресов: %v", err)
	}
	if rows != 1 {
		t.Errorf("адресов после повтора = %d, want 1", rows)
	}

	// Тот же ключ, другое тело — конфликт, а не тихий повтор.
	other := seedServer(t, ctx, q, "10.96.51.0/29")
	setServerOnline(t, ctx, q, other.ID)
	w = issueViaHTTP(t, h, user, device, other.ID, key)
	if w.Code != http.StatusConflict || decodeErr(t, w).Error.Code != "idempotency_key_conflict" {
		t.Fatalf("ключ переиспользован с другим телом: %d %s", w.Code, w.Body)
	}

	// Другой ключ, та же пара (устройство, сервер) — конфликт уже выданного профиля.
	w = issueViaHTTP(t, h, user, device, srv.ID, uuid.NewString())
	if w.Code != http.StatusConflict || decodeErr(t, w).Error.Code != "conflict" {
		t.Fatalf("повторная выдача на ту же пару: %d %s", w.Code, w.Body)
	}

	// Сервер не online — отдельный код: «выбери другой сервер», а не «повтори этот».
	maint := seedServer(t, ctx, q, "10.96.52.0/29")
	w = issueViaHTTP(t, h, user, seedDevice(t, ctx, q, user, 1).ID, maint.ID, uuid.NewString())
	if w.Code != http.StatusConflict || decodeErr(t, w).Error.Code != "server_not_available" {
		t.Fatalf("выдача на maintenance: %d %s", w.Code, w.Body)
	}

	// Без подписки — 403, а не 404: подписка есть у аккаунта, а не у объекта.
	plain := seedUser(t, ctx, q, false)
	w = issueViaHTTP(t, h, plain, seedDevice(t, ctx, q, plain, 0).ID, srv.ID, uuid.NewString())
	if w.Code != http.StatusForbidden || decodeErr(t, w).Error.Code != "forbidden" {
		t.Fatalf("выдача без подписки: %d %s", w.Code, w.Body)
	}
}

func TestProfilesHTTPReadConfigAndRevoke(t *testing.T) {
	ctx := context.Background()
	q := db.New(pool(t))
	srv := seedServer(t, ctx, q, "10.96.53.0/29")
	setServerOnline(t, ctx, q, srv.ID)
	user := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, user, 0).ID
	h := profilesHTTP(t, httpx.NewIdempotency(httpx.NewPGIdempotency(pool(t))), nil)

	w := issueViaHTTP(t, h, user, device, srv.ID, uuid.NewString())
	if w.Code != http.StatusCreated {
		t.Fatalf("выдача = %d %s", w.Code, w.Body)
	}
	issued := decodeProfile(t, w)

	w = call(h, user, http.MethodGet, "/api/v1/devices/"+device.String()+"/profiles", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("список = %d %s", w.Code, w.Body)
	}
	var list struct {
		Profiles []map[string]any `json:"profiles"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("список не распаковывается: %v — %s", err, w.Body)
	}
	if len(list.Profiles) != 1 || list.Profiles[0]["status"] != "active" {
		t.Fatalf("в списке %d профилей: %s", len(list.Profiles), w.Body)
	}

	cfgPath := "/api/v1/devices/" + device.String() + "/profiles/" + srv.ID.String() + "/config"
	w = call(h, user, http.MethodGet,
		"/api/v1/devices/"+device.String()+"/profiles/"+srv.ID.String(), "", "")
	if w.Code != http.StatusOK || decodeProfile(t, w)["id"] != issued["id"] {
		t.Fatalf("чтение профиля: %d %s", w.Code, w.Body)
	}

	w = call(h, user, http.MethodGet, cfgPath, "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("конфиг = %d %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type конфига = %q, want text/plain; charset=utf-8", ct)
	}
	// Конфиг — доступ, который отзывают. Кэш посредника не имеет права вернуть его
	// после отзыва, поэтому ответ не кэшируется ни при каких условиях.
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control конфига = %q, want no-store", cc)
	}
	text := w.Body.String()
	for _, want := range []string{"[Interface]", "[Peer]", "PrivateKey"} {
		// Проверка разная для каждого токена: приватного ключа в тексте быть не
		// должно, остального — обязано.
		if want == "PrivateKey" {
			if strings.Contains(text, want) {
				t.Errorf("в конфиге клиента появился %s:\n%s", want, text)
			}
			continue
		}
		if !strings.Contains(text, want) {
			t.Errorf("в конфиге нет %q:\n%s", want, text)
		}
	}

	w = call(h, user, http.MethodDelete,
		"/api/v1/devices/"+device.String()+"/profiles/"+srv.ID.String(), "", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("отзыв = %d %s", w.Code, w.Body)
	}
	if strings.TrimSpace(w.Body.String()) != "" {
		t.Errorf("у 204 тело обязано быть пустым: %q", w.Body.String())
	}

	// Повторный отзыв — 409 с настоящим статусом: молчаливый 204 на второй отзыв
	// означал бы, что клиент не узнает о том, что доступ уже отобран.
	w = call(h, user, http.MethodDelete,
		"/api/v1/devices/"+device.String()+"/profiles/"+srv.ID.String(), "", "")
	e := decodeErr(t, w)
	if w.Code != http.StatusConflict || e.Error.Code != "conflict" || e.Error.Details["status"] != "revoked" {
		t.Fatalf("повторный отзыв: %d %s", w.Code, w.Body)
	}

	// Конфиг после отзыва — 409 (не 404): профиль существует и виден человеку.
	w = call(h, user, http.MethodGet, cfgPath, "", "")
	e = decodeErr(t, w)
	if w.Code != http.StatusConflict || e.Error.Code != "conflict" || e.Error.Details["status"] != "revoked" {
		t.Fatalf("конфиг после отзыва: %d %s", w.Code, w.Body)
	}
	// Тот же профиль через чтение остаётся доступным: отзыв видно, а не стирается.
	w = call(h, user, http.MethodGet,
		"/api/v1/devices/"+device.String()+"/profiles/"+srv.ID.String(), "", "")
	if w.Code != http.StatusOK || decodeProfile(t, w)["status"] != "revoked" {
		t.Fatalf("чтение отозванного профиля: %d %s", w.Code, w.Body)
	}
}

// TestProfilesHTTPRevokeRaceReportsActualStatus — статус, прочитанный до отзыва, к
// моменту отказа уже неверен. Гонку воспроизводит блокировка строки: обработчик
// успевает прочитать active и встать на UPDATE, а строка к его пробуждению уже
// revoked. Ответ обязан назвать настоящее состояние, а не сохранённую копию.
func TestProfilesHTTPRevokeRaceReportsActualStatus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := db.New(pool(t))
	srv := seedServer(t, ctx, q, "10.96.55.0/29")
	setServerOnline(t, ctx, q, srv.ID)
	user := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, user, 0).ID
	h := profilesHTTP(t, httpx.NewIdempotency(httpx.NewPGIdempotency(pool(t))), nil)

	w := issueViaHTTP(t, h, user, device, srv.ID, uuid.NewString())
	if w.Code != http.StatusCreated {
		t.Fatalf("выдача профиля: %d %s", w.Code, w.Body)
	}
	prof := decodeProfile(t, w)
	profileID := uuid.MustParse(prof["id"].(string))

	tx, err := pool(t).Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(ctx, `SELECT id FROM vpn_profiles WHERE id = $1 FOR UPDATE`, profileID); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("блокировка профиля: %v", err)
	}

	path := "/api/v1/devices/" + device.String() + "/profiles/" + srv.ID.String()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- call(h, user, http.MethodDelete, path, "", "")
	}()
	select {
	case got := <-done:
		_ = tx.Rollback(ctx)
		t.Fatalf("отзыв не ждал строку профиля: %d %s", got.Code, got.Body)
	case <-time.After(300 * time.Millisecond):
	}
	if _, err := tx.Exec(ctx,
		`UPDATE vpn_profiles SET status = 'revoked', revoked_at = now() WHERE id = $1`, profileID); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("отзыв профиля: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	select {
	case got := <-done:
		e := decodeErr(t, got)
		if got.Code != http.StatusConflict || e.Error.Code != "conflict" {
			t.Fatalf("отзыв отозванного на лету профиля = %d %s, want 409 conflict", got.Code, got.Body)
		}
		if e.Error.Details["status"] != "revoked" {
			t.Errorf("details.status = %v, want revoked: статус до гонки не должен уходить наружу",
				e.Error.Details["status"])
		}
	case <-time.After(30 * time.Second):
		t.Fatal("отзыв не завершился после снятия блокировки")
	}
}

func TestProfilesHTTPForeignDeviceIsUniformNotFound(t *testing.T) {
	ctx := context.Background()
	q := db.New(pool(t))
	srv := seedServer(t, ctx, q, "10.96.54.0/29")
	setServerOnline(t, ctx, q, srv.ID)
	owner := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, owner, 0).ID
	stranger := seedUserWithPlan(t, ctx, q, "internal-default")

	h := profilesHTTP(t, httpx.NewIdempotency(httpx.NewPGIdempotency(pool(t))), nil)
	// Профиль owner на этом сервере существует: чужой пользователь обязан получить
	// 404, а не «403 — да, такое устройство есть».
	if w := issueViaHTTP(t, h, owner, device, srv.ID, uuid.NewString()); w.Code != http.StatusCreated {
		t.Fatalf("выдача владельца: %d %s", w.Code, w.Body)
	}

	base := "/api/v1/devices/" + device.String() + "/profiles"
	type route struct {
		method, path, body, key string
	}
	routes := []route{
		{http.MethodPost, base, `{"server_id":"` + srv.ID.String() + `"}`, uuid.NewString()},
		{http.MethodGet, base, "", ""},
		{http.MethodGet, base + "/" + srv.ID.String(), "", ""},
		{http.MethodDelete, base + "/" + srv.ID.String(), "", ""},
		{http.MethodGet, base + "/" + srv.ID.String() + "/config", "", ""},
	}
	var firstCode string
	var firstMessage string
	for _, rt := range routes {
		w := call(h, stranger, rt.method, rt.path, rt.body, rt.key)
		e := decodeErr(t, w)
		if w.Code != http.StatusNotFound || e.Error.Code != "not_found" {
			t.Errorf("%s %s чужому устройству: %d %s", rt.method, rt.path, w.Code, w.Body)
			continue
		}
		if firstCode == "" {
			firstCode, firstMessage = e.Error.Code, e.Error.Message
			continue
		}
		// Одинаковый код и одинаковое сообщение на всех пяти маршрутах: по разному
		// тексту ответ можно было бы отличить «есть такое устройство» от «нет».
		if e.Error.Code != firstCode || e.Error.Message != firstMessage {
			t.Errorf("%s %s отвечает иначе: %q %q, want %q %q",
				rt.method, rt.path, e.Error.Code, e.Error.Message, firstCode, firstMessage)
		}
	}
}

func TestProfilesHTTPIssueLimitRunsBeforeIdempotencySlot(t *testing.T) {
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	srv := seedServer(t, ctx, q, "10.96.55.0/29")
	setServerOnline(t, ctx, q, srv.ID)
	user := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, user, 0).ID

	// Одно хранилище на два разных набора обёрток: смысл проверки в том, остался ли
	// слот свободным после отказа лимитера, а для него история должна быть общей.
	idem := httpx.NewIdempotency(httpx.NewPGIdempotency(p))

	// Ключ уникален на прогон: dev-база между запусками одна, и literal «shared-key»
	// оставил бы слот от прошлого прогона, который этот счёт посчитал бы вторым.
	key := uuid.NewString()

	denyAll := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Настоящий лимитер отвечает так же: конверт ошибки и 429, ничего не вызывая.
			httpx.WriteError(w, r, http.StatusTooManyRequests, httpx.ErrRateLimited, "лимит", nil)
		})
	}
	w := issueViaHTTP(t, profilesHTTP(t, idem, denyAll), user, device, srv.ID, key)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("запрос под лимитом: %d %s", w.Code, w.Body)
	}

	// Тот же ключ теперь проходит: если бы ограничитель стоял внутри обёртки
	// идемпотентности, первый отказ был бы записан как результат, и клиент получил
	// бы либо replay отказа, либо конфликт незавершённого слота.
	passthrough := func(next http.Handler) http.Handler { return next }
	w = issueViaHTTP(t, profilesHTTP(t, idem, passthrough), user, device, srv.ID, key)
	if w.Code != http.StatusCreated {
		t.Fatalf("тот же ключ после отказа лимитера: %d %s", w.Code, w.Body)
	}
	if strings.TrimSpace(w.Body.String()) == "" {
		t.Error("успешная выдача вернула пустое тело")
	}
	var slots int
	if err := p.QueryRow(ctx,
		"SELECT count(*) FROM idempotency_keys"+
			" WHERE user_id = $1 AND route = 'profile_issue' AND idem_key = $2",
		user, key).Scan(&slots); err != nil {
		t.Fatalf("count слотов идемпотентности: %v", err)
	}
	// Один слот — тот, что занял успешный запрос. Два означали бы, что отказ тоже
	// оставил запись.
	if slots != 1 {
		t.Errorf("слотов profile_issue с этим ключом = %d, want 1", slots)
	}
}
