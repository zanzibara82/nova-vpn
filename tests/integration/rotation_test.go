//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/novavpn/novavpn/internal/connections"
	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/devices"
	"github.com/novavpn/novavpn/internal/entitlements"
	"github.com/novavpn/novavpn/internal/httpx"
)

// nonCanonicalKey собирает ключ, у которого младшие биты последнего байта nonzero:
// в канонической base64 они spare, и валидатор обязан отклонить такую строку 400, а
// не пропустить её в уникальный индекс публичных ключей.
func nonCanonicalKey(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	sum[31] &= 0xFC // каноническая заготовка, иначе правка нашала бы на каноническую строку
	s := []byte(base64.StdEncoding.EncodeToString(sum[:]))
	// У 32 байт последний символ перед «=» несёт два spare-бита: выставляем младший, и
	// строка остаётся в алфавите base64, но перестаёт быть канонической кодировкой.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	i := len(s) - 2
	for k := 0; k < len(alphabet); k++ {
		if alphabet[k] == s[i] {
			s[i] = alphabet[k|1]
			break
		}
	}
	return string(s)
}

func rotationHTTP(t *testing.T) (http.Handler, *devices.Service) {
	t.Helper()
	p := pool(t)
	svc := devices.NewService(p, entitlements.New(db.New(p)))
	passthrough := func(next http.Handler) http.Handler { return next }
	dec := httpx.Decorators{Auth: passthrough, Anonymous: passthrough}
	mux := http.NewServeMux()
	devices.NewHandler(svc, httpx.NewIdempotency(httpx.NewPGIdempotency(p))).RegisterRoutes(mux, dec)
	return mux, svc
}

func rotateReq(h http.Handler, user, device uuid.UUID, publicKey, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/devices/"+device.String()+"/keys/rotate",
		strings.NewReader(`{"public_key":"`+publicKey+`"}`))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	req = req.Clone(httpx.WithUserID(req.Context(), user))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func decodeDevice(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("тело не является устройством: %v — %s", err, w.Body)
	}
	return v
}

func TestRotateKeyCarriesAddressAndOpensOverlap(t *testing.T) {
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	h, _ := rotationHTTP(t)

	user := seedUserWithPlan(t, ctx, q, "internal-default")
	parent := seedDevice(t, ctx, q, user, 0)
	srv := seedServer(t, ctx, q, "10.96.70.0/29")
	setServerOnline(t, ctx, q, srv.ID)
	old := profileOf(t, user, parent.ID, srv.ID)
	versionBefore := serverVersion(t, srv.ID)

	newKey := keyFromSeed("rotated-" + parent.ID.String())
	w := rotateReq(h, user, parent.ID, newKey, uuid.NewString())
	if w.Code != http.StatusOK {
		t.Fatalf("ротация = %d %s", w.Code, w.Body)
	}
	// 200, а не 201: создаётся не новый объект в терминах пользователя, а новое
	// состояние того же устройства.
	child := decodeDevice(t, w)
	if child["public_key"] != newKey {
		t.Errorf("потомок вернул ключ %v, want %v", child["public_key"], newKey)
	}
	childID := uuid.MustParse(child["id"].(string))

	var childRow db.Device
	if err := p.QueryRow(ctx,
		"SELECT id, user_id, rotation_of, revoked_at FROM devices WHERE id = $1", childID).
		Scan(&childRow.ID, &childRow.UserID, &childRow.RotationOf, &childRow.RevokedAt); err != nil {
		t.Fatalf("чтение потомка: %v", err)
	}
	if childRow.RotationOf == nil || *childRow.RotationOf != parent.ID {
		t.Errorf("rotation_of потомка = %v, want %v", childRow.RotationOf, parent.ID)
	}
	if childRow.RevokedAt != nil {
		t.Error("потомок создан уже отозванным")
	}

	var parentRevokedAt *time.Time
	var parentPlatform, parentName string
	if err := p.QueryRow(ctx,
		"SELECT revoked_at, platform, name FROM devices WHERE id = $1", parent.ID).
		Scan(&parentRevokedAt, &parentPlatform, &parentName); err != nil {
		t.Fatalf("чтение предка: %v", err)
	}
	if parentRevokedAt == nil {
		t.Error("предок не отозван")
	}
	// Платформа и имя наследуются: требовать их в теле значило бы дать клиенту
	// способ соврать про себя при смене ключа.
	if parentPlatform != child["platform"].(string) || parentName != child["name"].(string) {
		t.Errorf("потомок унаследовал не всё: %q/%q, want %q/%q",
			child["platform"], child["name"], parentPlatform, parentName)
	}

	// Профиль предка — superseded с открытым окном; профиль потомка — активен с тем
	// же адресом и тем же сроком: ротация ключа не продлевает доступ.
	var oldStatus, oldPeer string
	var overlap *time.Time
	if err := p.QueryRow(ctx,
		"SELECT status, peer_state, overlap_valid_until FROM vpn_profiles WHERE id = $1", old.ID).
		Scan(&oldStatus, &oldPeer, &overlap); err != nil {
		t.Fatalf("чтение профиля предка: %v", err)
	}
	if oldStatus != "superseded" || oldPeer != "rotating_old_key" {
		t.Errorf("профиль предка: %q/%q, want superseded/rotating_old_key", oldStatus, oldPeer)
	}
	if overlap == nil {
		t.Fatal("окно overlap не открыто")
	}
	left := time.Until(*overlap)
	if left < connections.RotationOverlap-30*time.Second || left > connections.RotationOverlap+30*time.Second {
		t.Errorf("до конца overlap %v, want около %v", left, connections.RotationOverlap)
	}

	var childProfile struct {
		ID         uuid.UUID
		Address    netip.Addr
		Status     string
		RotateFrom *uuid.UUID
		ExpiresAt  time.Time
	}
	if err := p.QueryRow(ctx,
		"SELECT id, address_v4, status, rotate_from, expires_at FROM vpn_profiles"+
			" WHERE device_id = $1 AND server_id = $2", childID, srv.ID).
		Scan(&childProfile.ID, &childProfile.Address, &childProfile.Status,
			&childProfile.RotateFrom, &childProfile.ExpiresAt); err != nil {
		t.Fatalf("чтение профиля потомка: %v", err)
	}
	if childProfile.Status != "active" {
		t.Errorf("профиль потомка = %q, want active", childProfile.Status)
	}
	if childProfile.Address != old.AddressV4 {
		t.Errorf("адрес потомка %v, want тот же %v", childProfile.Address, old.AddressV4)
	}
	if childProfile.RotateFrom == nil || *childProfile.RotateFrom != old.ID {
		t.Errorf("rotate_from = %v, want профиль предка %v", childProfile.RotateFrom, old.ID)
	}
	if !childProfile.ExpiresAt.Equal(old.ExpiresAt) {
		t.Errorf("срок потомка %v, want тот же %v", childProfile.ExpiresAt, old.ExpiresAt)
	}

	// Строка аллокации перешла к потомку: иначе закрытие overlap освободило бы
	// адрес, по которому клиент уже ходит.
	var allocated *uuid.UUID
	if err := p.QueryRow(ctx,
		"SELECT allocated_to FROM tunnel_addresses WHERE server_id = $1 AND address = $2",
		srv.ID, old.AddressV4).Scan(&allocated); err != nil {
		t.Fatalf("чтение строки адреса: %v", err)
	}
	if allocated == nil || *allocated != childProfile.ID {
		t.Errorf("адрес закреплён за %v, want профиль потомка %v", allocated, childProfile.ID)
	}

	if got := serverVersion(t, srv.ID); got != versionBefore+1 {
		t.Errorf("config_version = %d, want %d", got, versionBefore+1)
	}
	detail := eventDetail(t, p, srv.ID, "profile_issued")
	if !strings.Contains(detail, old.ID.String()) {
		t.Errorf("в событии выдачи нет rotated_from (%v): %s", old.ID, detail)
	}
}

func TestRotateKeyDoesNotConsumeDeviceLimit(t *testing.T) {
	ctx := context.Background()
	q := db.New(pool(t))
	h, _ := rotationHTTP(t)

	user := seedUserWithPlan(t, ctx, q, "internal-default")
	ent, err := entitlements.New(db.New(pool(t))).ForUser(ctx, user)
	if err != nil {
		t.Fatalf("ForUser: %v", err)
	}
	// До отказа: devices создаются ровно до лимита, и ротация проверяется на нём,
	// а не «где-нибудь».
	deviceIDs := make([]uuid.UUID, 0, ent.DeviceLimit)
	for i := 0; i < ent.DeviceLimit; i++ {
		deviceIDs = append(deviceIDs, seedDevice(t, ctx, q, user, i).ID)
	}
	live, err := db.New(pool(t)).CountLiveDevices(ctx, user)
	if err != nil {
		t.Fatalf("CountLiveDevices: %v", err)
	}
	if int(live) != ent.DeviceLimit {
		t.Fatalf("живых устройств %d, want %d — фикстура не на лимите", live, ent.DeviceLimit)
	}

	srv := seedServer(t, ctx, q, "10.96.71.0/29")
	setServerOnline(t, ctx, q, srv.ID)
	profileOf(t, user, deviceIDs[0], srv.ID)

	w := rotateReq(h, user, deviceIDs[0], keyFromSeed("on-limit-"+deviceIDs[0].String()), uuid.NewString())
	if w.Code != http.StatusOK {
		t.Fatalf("ротация на лимите = %d %s, want 200", w.Code, w.Body)
	}
	// Предок отзывается в той же транзакции, поэтому живых осталось ровно столько же:
	// это и есть решение §4 — без него ротация на исчерпанном лимите была бы невозможна.
	live, err = db.New(pool(t)).CountLiveDevices(ctx, user)
	if err != nil {
		t.Fatalf("CountLiveDevices: %v", err)
	}
	if int(live) != ent.DeviceLimit {
		t.Errorf("живых устройств после ротации = %d, want %d", live, ent.DeviceLimit)
	}
}

// TestRotateKeyWaitsForUserDeviceLock — ротация читает предка и вставляет ребёнка под
// тем же advisory lock пользователя, что и Register. Без него две параллельные
// ротации одного предка обе видели бы его живым: первая отзывала бы предка, а вторая
// всё равно вставляла ребёнка, и живых устройств становилось бы на одно больше лимита.
func TestRotateKeyWaitsForUserDeviceLock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	svc, q := newDeviceSvc(t)
	user := seedUser(t, ctx, q, true)
	parent := seedDevice(t, ctx, q, user, 0)

	tx, err := pool(t).Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, user.String()); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("advisory lock: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := svc.RotateKey(ctx, user, parent.ID, keyFromSeed("locked-"+parent.ID.String()))
		done <- err
	}()
	select {
	case err := <-done:
		_ = tx.Rollback(ctx)
		t.Fatalf("ротация не ждала advisory lock пользователя: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ротация после снятия блокировки: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("ротация не завершилась после снятия блокировки")
	}
}

func TestRotateKeyWithoutProfiles(t *testing.T) {
	ctx := context.Background()
	q := db.New(pool(t))
	h, _ := rotationHTTP(t)

	user := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, user, 0).ID
	srv := seedServer(t, ctx, q, "10.96.72.0/29")
	setServerOnline(t, ctx, q, srv.ID)
	versionBefore := serverVersion(t, srv.ID)

	w := rotateReq(h, user, device, keyFromSeed("bare-"+device.String()), uuid.NewString())
	if w.Code != http.StatusOK {
		t.Fatalf("ротация устройства без профилей = %d %s", w.Code, w.Body)
	}
	childID := uuid.MustParse(decodeDevice(t, w)["id"].(string))
	var profiles int
	if err := pool(t).QueryRow(ctx,
		"SELECT count(*) FROM vpn_profiles WHERE device_id = ANY($1::uuid[])",
		[]uuid.UUID{device, childID}).Scan(&profiles); err != nil {
		t.Fatalf("count профилей: %v", err)
	}
	if profiles != 0 {
		t.Errorf("профилей появилось %d, want 0", profiles)
	}
	// Менять нечего — версия не двигается: bump без изменения набора пиеров заставил
	// бы каждый узел перечитать то же самое.
	if got := serverVersion(t, srv.ID); got != versionBefore {
		t.Errorf("config_version = %d, want %d (профилей не было)", got, versionBefore)
	}
}

func TestRotateKeyRefusesBadStates(t *testing.T) {
	ctx := context.Background()
	q := db.New(pool(t))
	h, _ := rotationHTTP(t)

	user := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, user, 0).ID
	stranger := seedUserWithPlan(t, ctx, q, "internal-default")

	// Чужое устройство — 404, а не «403, такое id существует».
	if w := rotateReq(h, stranger, device, keyFromSeed("x"), uuid.NewString()); w.Code != http.StatusNotFound {
		t.Errorf("ротация чужого устройства = %d %s, want 404", w.Code, w.Body)
	}

	// Неканонический ключ — 400 с названием поля: spare-биты последнего символа
	// отличают годный ключ от «похожей строки».
	w := rotateReq(h, user, device, nonCanonicalKey(device.String()), uuid.NewString())
	if w.Code != http.StatusBadRequest {
		t.Errorf("неканонический ключ = %d %s, want 400", w.Code, w.Body)
	}
	if body := w.Body.String(); !strings.Contains(body, `"public_key"`) {
		t.Errorf("в отказе не названо поле public_key: %s", body)
	}

	// Без Idempotency-Key — 400 до всякой обёртки.
	if w := rotateReq(h, user, device, keyFromSeed("no-key"), ""); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "idempotency_key_required") {
		t.Errorf("ротация без ключа = %d %s", w.Code, w.Body)
	}

	// Дубликат ключа живого устройства — 409 duplicate_device, и потомок не создан:
	// отказ, после которого осталась строка устройства, был бы второй дырой.
	other := seedDevice(t, ctx, q, user, 1)
	w = rotateReq(h, user, device, other.PublicKey, uuid.NewString())
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"duplicate_device"`) {
		t.Fatalf("ротация на чужой ключ = %d %s", w.Code, w.Body)
	}
	var children int
	if err := pool(t).QueryRow(ctx,
		"SELECT count(*) FROM devices WHERE rotation_of = $1", device).Scan(&children); err != nil {
		t.Fatalf("count потомков: %v", err)
	}
	if children != 0 {
		t.Errorf("потомков создано %d, want 0 — отказ обязан не оставлять следа", children)
	}

	// Отозванное устройство — 409 с причиной: человек должен понять, что сначала
	// нужно зарегистрировать новое устройство, а не повторять запрос.
	if err := q.RevokeDevice(ctx, device); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	w = rotateReq(h, user, device, keyFromSeed("after-revoke"), uuid.NewString())
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "device_revoked") {
		t.Errorf("ротация отозванного = %d %s", w.Code, w.Body)
	}
}

func TestRotateKeyIsIdempotentPerKey(t *testing.T) {
	ctx := context.Background()
	q := db.New(pool(t))
	h, _ := rotationHTTP(t)

	user := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, user, 0).ID
	key := uuid.NewString()
	publicKey := keyFromSeed("idem-" + device.String())

	first := rotateReq(h, user, device, publicKey, key)
	if first.Code != http.StatusOK {
		t.Fatalf("первая ротация = %d %s", first.Code, first.Body)
	}
	replay := rotateReq(h, user, device, publicKey, key)
	if replay.Code != http.StatusOK || replay.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("повтор = %d replayed=%q %s", replay.Code, replay.Header().Get("Idempotency-Replayed"), replay.Body)
	}
	if decodeDevice(t, replay)["id"] != decodeDevice(t, first)["id"] {
		t.Error("повтор вернул другое устройство вместо сохранённого результата")
	}
	var children int
	if err := pool(t).QueryRow(ctx,
		"SELECT count(*) FROM devices WHERE rotation_of = $1", device).Scan(&children); err != nil {
		t.Fatalf("count потомков: %v", err)
	}
	if children != 1 {
		t.Errorf("потомков = %d, want 1: повтор с тем же ключом не создаёт второго", children)
	}
}

func TestRotationChainOfThreeDevicesEndsAtMiddleDelete(t *testing.T) {
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	h, svc := rotationHTTP(t)

	user := seedUserWithPlan(t, ctx, q, "internal-default")
	first := seedDevice(t, ctx, q, user, 0)
	srv := seedServer(t, ctx, q, "10.96.73.0/29")
	setServerOnline(t, ctx, q, srv.ID)
	profileOf(t, user, first.ID, srv.ID)

	// Две последовательные ротации: цепочка из трёх устройств, у каждого — профиль с
	// тем же адресом.
	ids := []uuid.UUID{first.ID}
	current := first.ID
	for i := 0; i < 2; i++ {
		w := rotateReq(h, user, current, keyFromSeed("chain-"+current.String()), uuid.NewString())
		if w.Code != http.StatusOK {
			t.Fatalf("ротация %d = %d %s", i+1, w.Code, w.Body)
		}
		next := uuid.MustParse(decodeDevice(t, w)["id"].(string))
		ids = append(ids, next)
		current = next
	}

	// Активным остаётся последнее устройство цепочки: каждая ротация отзывает предка.
	// Именно его отзыв обязан погасить всю цепочку и закрыть overlap всех предков,
	// поэтому обход проверяется от живого узла, а удаление — тоже от него.
	middle := ids[len(ids)-1]
	ancestors, err := q.RotationAncestorIDs(ctx, middle)
	if err != nil {
		t.Fatalf("RotationAncestorIDs: %v", err)
	}
	descendants, err := q.RotationDescendantIDs(ctx, middle)
	if err != nil {
		t.Fatalf("RotationDescendantIDs: %v", err)
	}
	inChain := map[uuid.UUID]bool{}
	for _, id := range append(ancestors, descendants...) {
		inChain[id] = true
	}
	for i, id := range ids {
		if !inChain[id] {
			t.Errorf("устройство %d (%v) не попало в цепочку", i, id)
		}
	}
	if len(inChain) != 3 {
		t.Errorf("цепочка = %d устройств, want 3", len(inChain))
	}

	if _, err := svc.DeleteDevice(ctx, user, middle); err != nil {
		t.Fatalf("DeleteDevice среднего: %v", err)
	}
	var live int
	if err := p.QueryRow(ctx,
		"SELECT count(*) FROM devices WHERE id = ANY($1::uuid[]) AND revoked_at IS NULL",
		ids).Scan(&live); err != nil {
		t.Fatalf("count живых в цепочке: %v", err)
	}
	if live != 0 {
		t.Errorf("живых устройств в цепочке осталось %d, want 0", live)
	}
	var activeProfiles int
	if err := p.QueryRow(ctx,
		"SELECT count(*) FROM vpn_profiles WHERE device_id = ANY($1::uuid[]) AND status = 'active'",
		ids).Scan(&activeProfiles); err != nil {
		t.Fatalf("count активных профилей: %v", err)
	}
	if activeProfiles != 0 {
		t.Errorf("активных профилей осталось %d, want 0", activeProfiles)
	}
	// Адрес по-прежнему занят ровно одним профилем: цепочка гасится, но строка
	// аллокации не должна ни удвоиться, ни исчезнуть без окна переиспользования.
	var rows, withWindow int
	if err := p.QueryRow(ctx,
		"SELECT count(*), count(*) FILTER (WHERE reusable_at IS NOT NULL AND allocated_to IS NULL)"+
			" FROM tunnel_addresses WHERE server_id = $1", srv.ID).
		Scan(&rows, &withWindow); err != nil {
		t.Fatalf("count адресов: %v", err)
	}
	if rows != 1 || withWindow != 1 {
		t.Errorf("строк адресов = %d (с окном %d), want 1 и 1", rows, withWindow)
	}
}
