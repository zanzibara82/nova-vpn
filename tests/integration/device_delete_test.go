//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/novavpn/novavpn/internal/connections"
	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/devices"
	"github.com/novavpn/novavpn/internal/entitlements"
	"github.com/novavpn/novavpn/internal/httpx"
)

// deviceDeleteHTTP монтирует маршруты устройств с пропускающими обёртками: здесь
// проверяются отзыв цепочки, bump серверов и коды ответа, а не аутентификация.
func deviceDeleteHTTP(t *testing.T) (http.Handler, *devices.Service) {
	t.Helper()
	p := pool(t)
	svc := devices.NewService(p, entitlements.New(db.New(p)))
	passthrough := func(next http.Handler) http.Handler { return next }
	dec := httpx.Decorators{Auth: passthrough, Anonymous: passthrough}
	mux := http.NewServeMux()
	devices.NewHandler(svc, nil).RegisterRoutes(mux, dec)
	return mux, svc
}

func deleteDeviceReq(h http.Handler, user, device uuid.UUID) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/"+device.String(), nil)
	req = req.Clone(httpx.WithUserID(req.Context(), user))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// profileOf создаёт активный профиль выдачей через сервис профилей — тем же путём,
// каким его создаёт продукт. Вставка строки напрямую обошла бы аллокацию, и тест
// проверял бы состояние, которого выдача не производит.
func profileOf(t *testing.T, user, device, server uuid.UUID) db.VpnProfile {
	t.Helper()
	p := pool(t)
	svc := connectionsServiceForTest(t, p)
	prof, err := svc.Issue(context.Background(), user, device, server)
	if err != nil {
		t.Fatalf("выдача профиля на сервер %v: %v", server, err)
	}
	return prof
}

func connectionsServiceForTest(t *testing.T, p *pgxpool.Pool) *connections.Service {
	t.Helper()
	return connections.NewService(p, entitlements.New(db.New(p)))
}

func serverVersion(t *testing.T, id uuid.UUID) int64 {
	t.Helper()
	var v int64
	if err := pool(t).QueryRow(context.Background(),
		"SELECT config_version FROM vpn_servers WHERE id = $1", id).Scan(&v); err != nil {
		t.Fatalf("config_version сервера %v: %v", id, err)
	}
	return v
}

func TestDeleteDeviceRevokesProfilesAndBumpsServers(t *testing.T) {
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	h, _ := deviceDeleteHTTP(t)

	user := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, user, 0).ID
	srvA := seedServer(t, ctx, q, "10.96.60.0/29")
	srvB := seedServer(t, ctx, q, "10.96.61.0/29")
	setServerOnline(t, ctx, q, srvA.ID)
	setServerOnline(t, ctx, q, srvB.ID)
	profA := profileOf(t, user, device, srvA.ID)
	profB := profileOf(t, user, device, srvB.ID)

	versionA, versionB := serverVersion(t, srvA.ID), serverVersion(t, srvB.ID)
	eventsBefore := eventCount(t, p, srvA.ID, "profile_revoked") +
		eventCount(t, p, srvB.ID, "profile_revoked")

	w := deleteDeviceReq(h, user, device)
	if w.Code != http.StatusNoContent {
		t.Fatalf("отзыв устройства = %d %s", w.Code, w.Body)
	}
	if strings.TrimSpace(w.Body.String()) != "" {
		t.Errorf("у 204 тело обязано быть пустым: %q", w.Body.String())
	}

	// Оба профиля отозваны, и оба сервера подняли версию: узел, который не получил
	// bump, держал бы пиера с отозванным ключом.
	for _, prof := range []db.VpnProfile{profA, profB} {
		var status string
		var revokedAt *time.Time
		if err := p.QueryRow(ctx,
			"SELECT status, revoked_at FROM vpn_profiles WHERE id = $1", prof.ID).
			Scan(&status, &revokedAt); err != nil {
			t.Fatalf("чтение профиля %v: %v", prof.ID, err)
		}
		if status != "revoked" || revokedAt == nil {
			t.Errorf("профиль %v: status = %q, revoked_at = %v, want revoked и отметка",
				prof.ID, status, revokedAt)
		}
		// Адрес освобождён, но строка остаётся с окном переиспользования (§7.2).
		var allocated *uuid.UUID
		var reusable *time.Time
		if err := p.QueryRow(ctx,
			"SELECT allocated_to, reusable_at FROM tunnel_addresses WHERE server_id = $1 AND address = $2",
			prof.ServerID, prof.AddressV4).Scan(&allocated, &reusable); err != nil {
			t.Fatalf("строка адреса %v: %v", prof.AddressV4, err)
		}
		if allocated != nil {
			t.Errorf("адрес %v всё ещё закреплён за %v", prof.AddressV4, allocated)
		}
		if reusable == nil {
			t.Errorf("у адреса %v не открыто окно переиспользования", prof.AddressV4)
		}
	}
	if got := serverVersion(t, srvA.ID); got != versionA+1 {
		t.Errorf("config_version сервера A = %d, want %d", got, versionA+1)
	}
	if got := serverVersion(t, srvB.ID); got != versionB+1 {
		t.Errorf("config_version сервера B = %d, want %d", got, versionB+1)
	}
	eventsAfter := eventCount(t, p, srvA.ID, "profile_revoked") +
		eventCount(t, p, srvB.ID, "profile_revoked")
	if eventsAfter-eventsBefore != 2 {
		t.Errorf("новых событий profile_revoked = %d, want 2", eventsAfter-eventsBefore)
	}

	// Устройство не стирается: revoked_at отметка, а не DELETE строки — по отметке
	// судят, когда доступ перестал существовать.
	var revokedAt *time.Time
	if err := p.QueryRow(ctx, "SELECT revoked_at FROM devices WHERE id = $1", device).
		Scan(&revokedAt); err != nil {
		t.Fatalf("чтение устройства: %v", err)
	}
	if revokedAt == nil {
		t.Error("revoked_at у устройства не выставлен")
	}
}

func TestDeleteDeviceReturnsCountOfRevokedProfiles(t *testing.T) {
	ctx := context.Background()
	q := db.New(pool(t))
	_, svc := deviceDeleteHTTP(t)
	user := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, user, 0).ID
	srv := seedServer(t, ctx, q, "10.96.62.0/29")
	setServerOnline(t, ctx, q, srv.ID)
	profileOf(t, user, device, srv.ID)

	n, err := svc.DeleteDevice(ctx, user, device)
	if err != nil {
		t.Fatalf("DeleteDevice: %v", err)
	}
	if n != 1 {
		t.Errorf("отозвано профилей = %d, want 1", n)
	}
	// Второй вызов того же устройства — отказ, а не «ноль профилей и успех»:
	// молчаливый ноль стёр бы разницу между «устройство отозвано» и «профилей не было».
	if _, err := svc.DeleteDevice(ctx, user, device); !errors.Is(err, devices.ErrDeviceRevoked) {
		t.Errorf("повторный отзыв: err = %v, want ErrDeviceRevoked", err)
	}
}

func TestDeleteDeviceClosesWholeRotationChain(t *testing.T) {
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	h, _ := deviceDeleteHTTP(t)

	user := seedUserWithPlan(t, ctx, q, "internal-default")
	parent := seedDevice(t, ctx, q, user, 0)
	// Потомок ротации: «то же устройство с новым ключом». Вставка через запрос, а не
	// ручной правкой: rotation_of — часть того же контракта, что и публичный ключ.
	child, err := q.InsertDevice(ctx, db.InsertDeviceParams{
		ID: uuid.New(), UserID: user, PublicKey: keyFromSeed("child-" + parent.ID.String()),
		Platform: db.DevicePlatformLinux, Name: "child", RotationOf: &parent.ID,
	})
	if err != nil {
		t.Fatalf("InsertDevice потомка: %v", err)
	}
	grandchild, err := q.InsertDevice(ctx, db.InsertDeviceParams{
		ID: uuid.New(), UserID: user, PublicKey: keyFromSeed("grand-" + child.ID.String()),
		Platform: db.DevicePlatformLinux, Name: "grand", RotationOf: &child.ID,
	})
	if err != nil {
		t.Fatalf("InsertDevice внука: %v", err)
	}

	srv := seedServer(t, ctx, q, "10.96.63.0/29")
	setServerOnline(t, ctx, q, srv.ID)
	profileOf(t, user, parent.ID, srv.ID)
	profileOf(t, user, child.ID, srv.ID)

	// Отзывается средний узел цепочки: вместе с ним обязан уйти и предок (окно
	// overlap закрыто), и потомок (для пользователя это то же устройство).
	w := deleteDeviceReq(h, user, child.ID)
	if w.Code != http.StatusNoContent {
		t.Fatalf("отзыв среднего узла = %d %s", w.Code, w.Body)
	}
	for _, id := range []uuid.UUID{parent.ID, child.ID, grandchild.ID} {
		var revoked *time.Time
		if err := p.QueryRow(ctx, "SELECT revoked_at FROM devices WHERE id = $1", id).
			Scan(&revoked); err != nil {
			t.Fatalf("чтение устройства %v: %v", id, err)
		}
		if revoked == nil {
			t.Errorf("устройство %v из цепочки не отозвано", id)
		}
	}
	var profiles, activeProfiles int
	if err := p.QueryRow(ctx,
		"SELECT count(*) FROM vpn_profiles WHERE device_id = ANY($1::uuid[])",
		[]uuid.UUID{parent.ID, child.ID, grandchild.ID}).Scan(&profiles); err != nil {
		t.Fatalf("count профилей цепочки: %v", err)
	}
	if err := p.QueryRow(ctx,
		"SELECT count(*) FROM vpn_profiles WHERE device_id = ANY($1::uuid[]) AND status = 'active'",
		[]uuid.UUID{parent.ID, child.ID, grandchild.ID}).Scan(&activeProfiles); err != nil {
		t.Fatalf("count активных профилей: %v", err)
	}
	if profiles != 2 || activeProfiles != 0 {
		t.Errorf("профилей = %d (активных %d), want 2 и 0", profiles, activeProfiles)
	}
	// Адрес не освобождён дважды: на каждый адрес ровно одна строка в таблице —
	// иначе повторный отзыв оставил бы «призрачную» строку и занял бы слот пула.
	var rows, distinct int
	if err := p.QueryRow(ctx,
		"SELECT count(*), count(DISTINCT address) FROM tunnel_addresses WHERE server_id = $1",
		srv.ID).Scan(&rows, &distinct); err != nil {
		t.Fatalf("count адресов сервера: %v", err)
	}
	if rows != 2 || rows != distinct {
		t.Errorf("строк адресов = %d, различных = %d, want 2 и 2", rows, distinct)
	}
}

func TestDeleteDeviceSupersedesOverlapProfile(t *testing.T) {
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	h, _ := deviceDeleteHTTP(t)

	user := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, user, 0).ID
	srv := seedServer(t, ctx, q, "10.96.64.0/29")
	setServerOnline(t, ctx, q, srv.ID)
	prof := profileOf(t, user, device, srv.ID)

	// Профиль помечен заменённым с открытым окном: именно такое состояние оставляет
	// ротация (задача 8), и отзыв устройства обязан закрыть его, а не оставить пиера
	// в desired set на всё окно.
	overlap := time.Now().Add(10 * time.Minute)
	if _, err := q.SupersedeProfile(ctx, db.SupersedeProfileParams{
		ID: prof.ID, OverlapValidUntil: &overlap,
	}); err != nil {
		t.Fatalf("SupersedeProfile: %v", err)
	}

	w := deleteDeviceReq(h, user, device)
	if w.Code != http.StatusNoContent {
		t.Fatalf("отзыв устройства с superseded-профилем = %d %s", w.Code, w.Body)
	}
	var status string
	if err := p.QueryRow(ctx, "SELECT status FROM vpn_profiles WHERE id = $1", prof.ID).
		Scan(&status); err != nil {
		t.Fatalf("чтение профиля: %v", err)
	}
	if status != "revoked" {
		t.Errorf("заменённый профиль остался %q, want revoked", status)
	}
}

// uniformNotFound проверяет, что отказ — 404 not_found с одним и тем же сообщением, и
// возвращает пару «код + сообщение» для сравнения двух ответов между собой.
func uniformNotFound(t *testing.T, what string, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: тело не является конвертом ошибки: %v — %s", what, err, w.Body)
	}
	if w.Code != http.StatusNotFound || body.Error.Code != "not_found" ||
		body.Error.Message != "устройство не найдено" {
		t.Errorf("%s: %d %q %q, want 404 not_found «устройство не найдено»",
			what, w.Code, body.Error.Code, body.Error.Message)
	}
	return body.Error.Code + "|" + body.Error.Message
}

func TestDeleteDeviceForeignAndUnknownAreIdentical(t *testing.T) {
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	h, _ := deviceDeleteHTTP(t)

	owner := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, owner, 0).ID
	stranger := seedUserWithPlan(t, ctx, q, "internal-default")

	before, err := q.DeviceByID(ctx, device)
	if err != nil {
		t.Fatalf("DeviceByID: %v", err)
	}

	foreign := deleteDeviceReq(h, stranger, device)
	unknown := deleteDeviceReq(h, stranger, uuid.New())
	// Сравниваются код состояния, код ошибки и сообщение — не всё тело: request_id в
	// конверте уникален на запрос, и полное сравнение тел падало бы всегда.
	foreignBody := uniformNotFound(t, "чужому устройству", foreign)
	unknownBody := uniformNotFound(t, "несуществующему устройству", unknown)
	if foreignBody != unknownBody {
		t.Errorf("чужое и неизвестное отвечают по-разному: %s против %s", foreignBody, unknownBody)
	}

	// Чужая попытка не изменила устройство: отказ, который что-то отозвал, был бы
	// худшим видом отказа.
	after, err := q.DeviceByID(ctx, device)
	if err != nil {
		t.Fatalf("DeviceByID после чужого запроса: %v", err)
	}
	if after.RevokedAt != nil || after.ID != before.ID {
		t.Errorf("устройство изменено чужим запросом: revoked_at = %v", after.RevokedAt)
	}

	// Повторный отзыв своим — 404: устройство уже отозвано, и успешный 204 на
	// второй вызов скрывал бы, что первый отзыв был.
	if w := deleteDeviceReq(h, owner, device); w.Code != http.StatusNoContent {
		t.Fatalf("первый отзыв своего устройства = %d %s", w.Code, w.Body)
	}
	if w := deleteDeviceReq(h, owner, device); w.Code != http.StatusNotFound {
		t.Errorf("повторный отзыв = %d %s, want 404", w.Code, w.Body)
	}

	// Не-uuid в пути — 400 с названием поля: 404 на опечатку прятал бы причину.
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/not-a-uuid", nil)
	req = req.Clone(httpx.WithUserID(req.Context(), owner))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), `"invalid_request"`) {
		t.Errorf("не-uuid в пути = %d %s", rec.Code, rec.Body)
	}
}

func TestDeleteDeviceKeepsRowButHidesFromList(t *testing.T) {
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	h, svc := deviceDeleteHTTP(t)

	user := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, user, 0).ID
	if w := deleteDeviceReq(h, user, device); w.Code != http.StatusNoContent {
		t.Fatalf("отзыв = %d %s", w.Code, w.Body)
	}

	// Контракт A-1: GET /devices отдаёт живых, поэтому отозванное устройство из
	// списка исчезает. Исчезнуть из базы оно не имеет права: по строкам судят, когда
	// доступ перестал существовать, и аудит ссылаются на device_id.
	list, err := svc.List(ctx, user)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, d := range list {
		if d.ID == device {
			t.Error("отозванное устройство вернулось в списке живых")
		}
	}
	var exists bool
	if err := p.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1)", device).Scan(&exists); err != nil {
		t.Fatalf("проверка строки устройства: %v", err)
	}
	if !exists {
		t.Error("отзыв удалил строку устройства вместо отметки")
	}
}
