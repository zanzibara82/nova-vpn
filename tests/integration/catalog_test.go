//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/httpx"
	"github.com/novavpn/novavpn/internal/servers"
)

// emptyDBTX — стаб, дающий ровно ноль строк на любом Query. Нужен одному случаю:
// «серверов нет → 200 {"servers":[]}». Проверять это на живой dev-базе нельзя: база
// между прогонами одна и та же, а каталог не фильтруется по пользователю, поэтому
// «пусто» означало бы «весь стек пуст» и зависело бы от порядка запуска тестов.
// Проверяемое свойство лежит в слое выдачи: пустой срез обязан сериализоваться в []
// и отдать 200, а не null и не 404. Запрос к БД в этом тесте не участвует ни в одном
// утверждении, поэтому подмена источника данных здесь честна.
type emptyDBTX struct{}

func (emptyDBTX) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (emptyDBTX) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return emptyRows{}, nil
}

func (emptyDBTX) QueryRow(context.Context, string, ...any) pgx.Row { return errRow{} }

type emptyRows struct{}

func (emptyRows) Close()                        {}
func (emptyRows) Err() error                    { return nil }
func (emptyRows) CommandTag() pgconn.CommandTag { return pgconn.CommandTag{} }
func (emptyRows) FieldDescriptions() []pgconn.FieldDescription {
	return nil
}
func (emptyRows) Next() bool { return false }
func (emptyRows) Scan(...any) error {
	return errors.New("emptyRows: строк нет")
}
func (emptyRows) Values() ([]any, error) { return nil, nil }
func (emptyRows) RawValues() [][]byte    { return nil }
func (emptyRows) Conn() *pgx.Conn        { return nil }
func (emptyRows) TypeMap() *pgtype.Map   { return nil }

type errRow struct{}

func (errRow) Scan(...any) error {
	return errors.New("errRow: каталог этот запрос не делает")
}

func catalogHandler(q *db.Queries) http.Handler {
	// dec — passthrough: закрытость маршрута доказывает матрица задачи 15, здесь
	// проверяется содержимое ответа.
	passthrough := func(next http.Handler) http.Handler { return next }
	dec := httpx.Decorators{Auth: passthrough, Anonymous: passthrough}
	mux := http.NewServeMux()
	servers.NewHandler(servers.NewService(q)).RegisterRoutes(mux, dec)
	return mux
}

// getCatalog разбирает ответ в []map[string]json.RawMessage, а не в struct:
// decode в типизированное поле не отличает «ключ absent» от «null», а различие
// «не измерено» / «не просили» — ровно то обещание, которое здесь проверяется.
func getCatalog(t *testing.T, h http.Handler, user uuid.UUID) (
	*httptest.ResponseRecorder, []map[string]json.RawMessage) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/servers", nil)
	req = req.Clone(httpx.WithUserID(req.Context(), user))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json; charset=utf-8", ct)
	}
	var decoded struct {
		Servers []map[string]json.RawMessage `json:"servers"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("разбор ответа каталога: %v (тело %s)", err, w.Body)
	}
	return w, decoded.Servers
}

func strField(t *testing.T, row map[string]json.RawMessage, key string) string {
	t.Helper()
	raw, ok := row[key]
	if !ok {
		t.Fatalf("ключ %q отсутствует в строке каталога", key)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return s
}

// wantNull утверждает именно JSON-null: ключ обязан присутствовать в ответе.
func wantNull(t *testing.T, row map[string]json.RawMessage, key string) {
	t.Helper()
	raw, ok := row[key]
	if !ok {
		t.Errorf("ключ %q отсутствует в ответе, want явный null", key)
		return
	}
	if string(raw) != "null" {
		t.Errorf("%s = %s, want null", key, raw)
	}
}

func wantNumber(t *testing.T, row map[string]json.RawMessage, key string, want float64) {
	t.Helper()
	raw, ok := row[key]
	if !ok {
		t.Errorf("ключ %q отсутствует в ответе", key)
		return
	}
	// numeric после override'а задачи 1 приходит в Go строкой, и тихая подача её
	// наружу была бы регрессией: карте клиента нужно JSON-число, а не "52.52".
	if len(raw) > 0 && (raw[0] == '"' || raw[0] == 'n') {
		t.Errorf("%s = %s, want JSON-число", key, raw)
		return
	}
	var got float64
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Errorf("%s: %v", key, err)
		return
	}
	if got != want {
		t.Errorf("%s = %v, want %v", key, got, want)
	}
}

func TestCatalogEmptyIs200WithEmptyArray(t *testing.T) {
	h := catalogHandler(db.New(emptyDBTX{}))
	w, rows := getCatalog(t, h, uuid.New())
	if w.Code != http.StatusOK {
		t.Fatalf("пустой каталог = %d %s, want 200", w.Code, w.Body)
	}
	if len(rows) != 0 {
		t.Fatalf("пустой каталог вернул %d строк", len(rows))
	}
	if got := strings.TrimSpace(w.Body.String()); got != `{"servers":[]}` {
		t.Fatalf("тело = %s, want {\"servers\":[]}", got)
	}
}

// Индексы фикстур: поиск в ответе идёт по позиции, а не по имени состояния, чтобы
// ни одна проверка не зависела от написания подписи.
const (
	fxMaintenance = iota
	fxOnlineNoHealth
	fxOnlineOKFresh
	fxOnlineOKLate
	fxHealthError
	fxHealthStale
	fxDraining
	fxRetired
	fxCount
)

type catalogFixture struct {
	online      bool
	finalState  *db.MaintenanceStatus
	health      *db.HealthStatus
	observedAgo time.Duration
	wantPresent bool
	wantAvail   servers.Availability
}

func TestCatalogMembershipAndAvailability(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	q := db.New(pool(t))
	now := time.Now()

	fixtures := [fxCount]catalogFixture{
		fxMaintenance: {wantPresent: false},
		fxOnlineNoHealth: {online: true, wantPresent: true,
			wantAvail: servers.AvailabilityUnknown},
		fxOnlineOKFresh: {online: true, wantPresent: true,
			wantAvail: servers.AvailabilityAvailable,
			health:    healthPtr(db.HealthStatusOk), observedAgo: 30 * time.Second},
		fxOnlineOKLate: {online: true, wantPresent: true,
			wantAvail:   servers.AvailabilityUnknown,
			health:      healthPtr(db.HealthStatusOk),
			observedAgo: 200 * time.Second},
		fxHealthError: {online: true, wantPresent: true,
			wantAvail: servers.AvailabilityUnknown,
			health:    healthPtr(db.HealthStatusError), observedAgo: 10 * time.Second},
		fxHealthStale: {online: true, wantPresent: true,
			wantAvail: servers.AvailabilityUnknown,
			health:    healthPtr(db.HealthStatusStale), observedAgo: 10 * time.Second},
		fxDraining: {online: true, finalState: msPtr(db.MaintenanceStatusDraining)},
		fxRetired:  {online: true, finalState: msPtr(db.MaintenanceStatusRetired)},
	}

	ids := [fxCount]uuid.UUID{}
	for i, f := range fixtures {
		// Свой /24 на фикстуру: пересечение пулов схемой не запрещено, но разные
		// сети делают случайную коллизию адресов видимой, а не молчаливой.
		srv := seedServer(t, ctx, q, fmt.Sprintf("10.95.%d.0/24", i))
		if f.online {
			setServerOnline(t, ctx, q, srv.ID)
		}
		if f.finalState != nil {
			if _, err := q.SetServerMaintenance(ctx, db.SetServerMaintenanceParams{
				ID: srv.ID, MaintenanceStatus: *f.finalState,
			}); err != nil {
				t.Fatalf("сервер %d: SetServerMaintenance(%s): %v", i, *f.finalState, err)
			}
		}
		if f.health != nil {
			seedHealth(t, ctx, q, srv.ID, *f.health, now.Add(-f.observedAgo))
		}
		ids[i] = srv.ID
	}

	// Каталог не фильтруется по пользователю, поэтому в ответе лежат и серверы
	// чужих прогонов: все утверждения идут по id конкретных фикстур, а не по длине
	// ответа.
	user := seedUser(t, ctx, q, true)
	_, rows := getCatalog(t, catalogHandler(q), user)
	index := make(map[string]map[string]json.RawMessage, len(rows))
	for _, row := range rows {
		index[strField(t, row, "id")] = row
	}

	for i, f := range fixtures {
		row, present := index[ids[i].String()]
		if !f.wantPresent {
			if present {
				t.Errorf("сервер %d: не-онлайн состояние %q попало в каталог", i, stateOf(f))
			}
			continue
		}
		if !present {
			t.Errorf("сервер %d: выведенный в online узел отсутствует в каталоге", i)
			continue
		}
		got := strField(t, row, "availability")
		if got != string(f.wantAvail) {
			t.Errorf("сервер %d: availability = %q, want %q", i, got, f.wantAvail)
		}
		// Значения «unavailable» у API нет ни при каком health (§1.2): оно было бы
		// утверждением о связности, которую контрол-плейн не измерял.
		if got == "unavailable" {
			t.Errorf("сервер %d: availability = unavailable, такого состояния контракта нет", i)
		}
	}

	// Обещание про неизмеренные числа — на фикстуре без health: у неё и
	// capacity_mbps не задан оператором.
	onlineRow := index[ids[fxOnlineNoHealth].String()]
	if onlineRow == nil {
		t.Fatal("фикстура без health не найдена — проверки формы ответа ниже нечего применить")
	}
	for _, key := range []string{"latency_ms", "load", "capacity_mbps"} {
		wantNull(t, onlineRow, key)
	}
	// Координаты вышли из server_locations строками (override numeric из задачи 1)
	// и обязаны быть числами: 52.5200 → 52.52.
	wantNumber(t, onlineRow, "latitude", 52.52)
	wantNumber(t, onlineRow, "longitude", 13.405)
	// region оператором не заполнен → "" , а не null: null клиент прочёл бы как
	// «поле не просили».
	if got := strField(t, onlineRow, "region"); got != "" {
		t.Errorf("region = %q, want пустая строка", got)
	}
	if got := strField(t, onlineRow, "country_code"); got != "DE" {
		t.Errorf("country_code = %q, want DE", got)
	}
}

func TestCatalogCarriesDeclaredServerFields(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := db.New(pool(t))

	srv := seedServer(t, ctx, q, "10.96.0.0/24")
	setServerOnline(t, ctx, q, srv.ID)
	seedHealth(t, ctx, q, srv.ID, db.HealthStatusOk, time.Now().Add(-5*time.Second))

	user := seedUser(t, ctx, q, true)
	w, rows := getCatalog(t, catalogHandler(q), user)
	if w.Code != http.StatusOK {
		t.Fatalf("каталог = %d %s", w.Code, w.Body)
	}
	var row map[string]json.RawMessage
	for _, r := range rows {
		if strField(t, r, "id") == srv.ID.String() {
			row = r
			break
		}
	}
	if row == nil {
		t.Fatal("онлайн-сервер не найден в каталоге")
	}
	if v := strField(t, row, "availability"); v != string(servers.AvailabilityAvailable) {
		t.Fatalf("availability = %q, want available (health ok, 5 с назад)", v)
	}
	if v := strField(t, row, "name"); v != srv.Name {
		t.Errorf("name = %q, want %q", v, srv.Name)
	}
	if v := strField(t, row, "host"); v != srv.AdvertisedHost {
		t.Errorf("host = %q, want %q", v, srv.AdvertisedHost)
	}
	wantNumber(t, row, "port", float64(srv.ListenPort))
	wantNumber(t, row, "mtu", float64(srv.Mtu))
	// provider — декларация оператора, он обязан прийти и у доступного сервера.
	if v := strField(t, row, "provider"); v != "integration" {
		t.Errorf("provider = %q, want integration", v)
	}
	// Даже у available-сервера latency и load остаются null: «доступен» не даёт
	// права выдумывать числа (§13.4, ADR-006).
	wantNull(t, row, "latency_ms")
	wantNull(t, row, "load")
}

func seedHealth(t *testing.T, ctx context.Context, q *db.Queries, serverID uuid.UUID,
	status db.HealthStatus, observedAt time.Time) {
	t.Helper()
	if err := q.UpsertServerHealth(ctx, db.UpsertServerHealthParams{
		ServerID: serverID, ObservedAt: observedAt,
		AppliedConfigVersion: 1, Status: status,
	}); err != nil {
		t.Fatalf("UpsertServerHealth(%s): %v", status, err)
	}
}

func healthPtr(s db.HealthStatus) *db.HealthStatus       { return &s }
func msPtr(s db.MaintenanceStatus) *db.MaintenanceStatus { return &s }

// stateOf — подпись состояния для сообщения об ошибке у не-онлайн фикстуры.
func stateOf(f catalogFixture) string {
	if f.finalState != nil {
		return string(*f.finalState)
	}
	return "maintenance"
}
