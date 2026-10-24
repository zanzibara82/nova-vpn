//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/db/migrate"
	"github.com/novavpn/novavpn/migrations"
)

// latestMigration — номер последней миграции из embedded FS. Проверка «applied == 6»
// устаревала на каждой новой миграции и впадала в ошибку вида «0006 не применилась»,
// когда применился весь набор; здесь сравнивается именно полнота набора.
func latestMigration(t *testing.T) uint {
	t.Helper()
	names, err := fs.Glob(migrations.FS, "*.up.sql")
	if err != nil {
		t.Fatalf("чтение embedded FS миграций: %v", err)
	}
	var max uint64
	for _, name := range names {
		n, err := strconv.ParseUint(strings.SplitN(name, "_", 2)[0], 10, 64)
		if err != nil {
			t.Fatalf("имя миграции %q не числовое: %v", name, err)
		}
		if n > max {
			max = n
		}
	}
	if max == 0 {
		t.Fatal("в embedded FS нет ни одной миграции")
	}
	return uint(max)
}

// netFixture — пользователь, устройство и сервер. Меньше нельзя: профиль висит на
// устройстве (FK), а адрес — на сервере, и «есть что отзывать» появляется только с
// тремя объектами сразу.
type netFixture struct {
	user   uuid.UUID
	device uuid.UUID
	server db.VpnServer
}

func newNetFixture(t *testing.T, ctx context.Context, poolV4 string) netFixture {
	t.Helper()
	q := db.New(pool(t))
	user := seedUserWithPlan(t, ctx, q, "internal-default")
	return netFixture{
		user:   user,
		device: seedDevice(t, ctx, q, user, 0).ID,
		server: seedServer(t, ctx, q, poolV4),
	}
}

// addDevice — второе устройство того же пользователя. Нужен потому, что
// profiles_one_active_per_device_server не допускает двух активных профилей на одной
// паре (устройство, сервер): фикстура обязана уважать тот же инвариант, что и выдача.
func addDevice(t *testing.T, ctx context.Context, q *db.Queries, user uuid.UUID, i int) uuid.UUID {
	t.Helper()
	return seedDevice(t, ctx, q, user, i).ID
}

func claimAddr(q *db.Queries, ctx context.Context, serverID uuid.UUID, addr string, profile uuid.UUID) error {
	_, err := q.ClaimAddress(ctx, db.ClaimAddressParams{
		ServerID:    serverID,
		Address:     netip.MustParseAddr(addr),
		AllocatedTo: &profile,
	})
	return err
}

func TestClaimAddressIsExclusive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := db.New(pool(t))
	f := newNetFixture(t, ctx, "10.99.1.0/24")
	d2 := addDevice(t, ctx, q, f.user, 1)
	p1 := seedProfile(t, ctx, q, f.device, f.server.ID, "10.99.1.5", time.Hour)
	p2 := seedProfile(t, ctx, q, d2, f.server.ID, "10.99.1.6", time.Hour)

	if err := claimAddr(q, ctx, f.server.ID, "10.99.1.5", p1.ID); err != nil {
		t.Fatalf("первый claim: %v", err)
	}
	// Guard в ON CONFLICT: занятый адрес не возвращается и чужое назначение не
	// перетирается — иначе аллокатор «починил» бы коллизию молча.
	if err := claimAddr(q, ctx, f.server.ID, "10.99.1.5", p2.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("claim занятого адреса: err=%v, ожидался pgx.ErrNoRows", err)
	}
	got, err := q.AddressOfProfile(ctx, &p1.ID)
	if err != nil || got.String() != "10.99.1.5" {
		t.Fatalf("назначение p1 повреждено: addr=%v err=%v", got, err)
	}

	// Освобождение оставляет окно переиспользования (§7.2): адрес ещё нельзя брать.
	if err := q.ReleaseAddressByProfile(ctx, &p1.ID); err != nil {
		t.Fatalf("ReleaseAddressByProfile: %v", err)
	}
	if err := claimAddr(q, ctx, f.server.ID, "10.99.1.5", p2.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("claim в окне переиспользования: err=%v, ожидался pgx.ErrNoRows", err)
	}

	// Окно «истекло» без ожидания пяти минут: сдвигаются обе границы, потому что
	// addresses_window требует reusable_at >= released_at.
	if _, err := pool(t).Exec(ctx, `UPDATE tunnel_addresses
	    SET released_at = now() - interval '10 minutes',
	        reusable_at = now() - interval '5 minutes'
	  WHERE server_id = $1 AND address = $2`,
		f.server.ID, netip.MustParseAddr("10.99.1.5")); err != nil {
		t.Fatalf("сдвиг окна: %v", err)
	}
	if err := claimAddr(q, ctx, f.server.ID, "10.99.1.5", p2.ID); err != nil {
		t.Fatalf("claim после истечения окна: %v", err)
	}
}

func TestBusyAddressesCoversBothKinds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := db.New(pool(t))
	f := newNetFixture(t, ctx, "10.99.2.0/24")
	p := seedProfile(t, ctx, q, f.device, f.server.ID, "10.99.2.10", time.Hour)
	if err := claimAddr(q, ctx, f.server.ID, "10.99.2.10", p.ID); err != nil {
		t.Fatalf("claim: %v", err)
	}
	// Два освобождённых адреса различаются только знаком окна: выборка обязана
	// считать занятым и то, и другое, иначе окно переиспользования обходится.
	// released_at во всех строках раньше reusable_at: CHECK addresses_window не
	// допускает окна, которое уже закрылось к моменту открытия.
	for _, row := range []struct {
		addr     string
		released string
		window   string
	}{
		{"10.99.2.11", `now() - interval '5 minutes'`, `now() + interval '5 minutes'`},
		{"10.99.2.12", `now() - interval '10 minutes'`, `now() - interval '5 minutes'`},
	} {
		if _, err := pool(t).Exec(ctx, `INSERT INTO tunnel_addresses
		      (server_id, address, allocated_to, released_at, reusable_at)
		    VALUES ($1, $2, NULL, `+row.released+`, `+row.window+`)`,
			f.server.ID, netip.MustParseAddr(row.addr)); err != nil {
			t.Fatalf("вставка %s: %v", row.addr, err)
		}
	}
	busy, err := q.BusyAddresses(ctx, f.server.ID)
	if err != nil {
		t.Fatalf("BusyAddresses: %v", err)
	}
	if len(busy) != 2 {
		t.Fatalf("занято %v, ожидалось 2 (назначенный + неистёкшее окно)", busy)
	}
	var seen10, seen11 bool
	for _, a := range busy {
		switch a.String() {
		case "10.99.2.10":
			seen10 = true
		case "10.99.2.11":
			seen11 = true
		case "10.99.2.12":
			t.Errorf("адрес с истёкшим окном считается занятым: %v", a)
		}
	}
	if !seen10 || !seen11 {
		t.Errorf("в выборке нет ожидаемых адресов: назначен=%v окно=%v (%v)", seen10, seen11, busy)
	}
}

func TestConsumeBootstrapTokenIsOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := db.New(pool(t))
	f := newNetFixture(t, ctx, "10.99.4.0/24")

	secret := "bootstrap-" + uuid.New().String()
	sum := sha256.Sum256([]byte(secret))
	row, err := q.InsertBootstrapToken(ctx, db.InsertBootstrapTokenParams{
		ID:        uuid.New(),
		TokenHash: sum[:],
		ServerID:  f.server.ID,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("InsertBootstrapToken: %v", err)
	}
	srv, err := q.ConsumeBootstrapToken(ctx, row.ID)
	if err != nil {
		t.Fatalf("первый consume: %v", err)
	}
	if srv != f.server.ID {
		t.Fatalf("consume отдал сервер %v, ожидался %v", srv, f.server.ID)
	}
	// Одноразовость держится на UPDATE с used_at IS NULL: второй параллельный enroll
	// не получает строку, а не «видит, что токен уже взят».
	if _, err := q.ConsumeBootstrapToken(ctx, row.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("второй consume: err=%v, ожидался pgx.ErrNoRows", err)
	}
	// Задача 11 различает «просрочен» и «израсходован» именно здесь: время должно
	// остаться в строке, а не потеряться вместе с токеном.
	after, err := q.BootstrapTokenByHash(ctx, sum[:])
	if err != nil {
		t.Fatalf("BootstrapTokenByHash: %v", err)
	}
	if after.UsedAt == nil {
		t.Error("used_at не проставлен: «израсходован» неотличим от «не использован»")
	}
	if after.RevokedAt != nil {
		t.Errorf("revoked_at заполнен без отзыва: %v", after.RevokedAt)
	}
}

func TestDesiredCandidatesOnlyActiveSuperseded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := db.New(pool(t))
	f := newNetFixture(t, ctx, "10.99.5.0/24")

	active := seedProfile(t, ctx, q, f.device, f.server.ID, "10.99.5.1", time.Hour)
	superseded := seedProfile(t, ctx, q, addDevice(t, ctx, q, f.user, 1), f.server.ID, "10.99.5.2", time.Hour)
	revoked := seedProfile(t, ctx, q, addDevice(t, ctx, q, f.user, 2), f.server.ID, "10.99.5.3", time.Hour)
	expired := seedProfile(t, ctx, q, addDevice(t, ctx, q, f.user, 3), f.server.ID, "10.99.5.4", time.Hour)

	overlap := time.Now().Add(10 * time.Minute)
	if _, err := q.SupersedeProfile(ctx, db.SupersedeProfileParams{
		ID: superseded.ID, OverlapValidUntil: &overlap,
	}); err != nil {
		t.Fatalf("SupersedeProfile: %v", err)
	}
	if _, err := q.RevokeProfile(ctx, revoked.ID); err != nil {
		t.Fatalf("RevokeProfile: %v", err)
	}
	if _, err := q.MarkProfileExpired(ctx, expired.ID); err != nil {
		t.Fatalf("MarkProfileExpired: %v", err)
	}

	rows, err := q.DesiredCandidates(ctx, f.server.ID)
	if err != nil {
		t.Fatalf("DesiredCandidates: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("кандидатов %d, ожидалось 2 (active + superseded): %v", len(rows), statuses(rows))
	}
	for _, r := range rows {
		if r.Status != db.ProfileStatusActive && r.Status != db.ProfileStatusSuperseded {
			t.Errorf("статус %q в желаемом наборе", r.Status)
		}
		// Ключ устройства идёт из фикстуры: без него узлу не собрать [Peer].
		if r.PublicKey == "" {
			t.Errorf("профиль %v без публичного ключа", r.ID)
		}
		if r.RotateFrom != nil {
			t.Errorf("RotateFrom без ротации: %v", r.RotateFrom)
		}
		if r.ID == active.ID && r.Status != db.ProfileStatusActive {
			t.Errorf("профиль выдачи %v вернулся со статусом %q", r.ID, r.Status)
		}
	}
	if rows[0].AddressV4.Compare(rows[1].AddressV4) > 0 {
		t.Errorf("выборка не отсортирована по адресу: %v, %v", rows[0].AddressV4, rows[1].AddressV4)
	}
}

func statuses(rows []db.DesiredCandidatesRow) []db.ProfileStatus {
	out := make([]db.ProfileStatus, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Status)
	}
	return out
}

func TestRevokeProfilesForDevicesReturnsServers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := db.New(pool(t))
	f := newNetFixture(t, ctx, "10.99.6.0/24")
	other := seedServer(t, ctx, q, "10.99.7.0/24")

	seedProfile(t, ctx, q, f.device, f.server.ID, "10.99.6.1", time.Hour)
	seedProfile(t, ctx, q, f.device, other.ID, "10.99.7.1", time.Hour)

	rows, err := q.RevokeProfilesForDevices(ctx, []uuid.UUID{f.device})
	if err != nil {
		t.Fatalf("RevokeProfilesForDevices: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("отозвано %d профилей, ожидалось 2", len(rows))
	}
	// server_id в возврате — не украшение: по нему вызывающий код поднимает
	// config_version. Потерять второй сервер значит оставить живого пиера на узле.
	seen := map[uuid.UUID]bool{}
	for _, r := range rows {
		seen[r.ServerID] = true
	}
	if !seen[f.server.ID] || !seen[other.ID] {
		t.Errorf("сервера в возврате: %v (ожидались %v и %v)", seen, f.server.ID, other.ID)
	}
}

func TestUpsertServerHealthReplaces(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := db.New(pool(t))
	f := newNetFixture(t, ctx, "10.99.8.0/24")

	agent := "0.1.0"
	upsert := func(peers int32, version string) {
		t.Helper()
		if err := q.UpsertServerHealth(ctx, db.UpsertServerHealthParams{
			ServerID:             f.server.ID,
			ObservedAt:           time.Now(),
			PeersConfigured:      peers,
			PeersHandshaked:      peers - 1,
			InterfaceRxBytes:     1000,
			InterfaceTxBytes:     2000,
			AppliedConfigVersion: 7,
			Status:               db.HealthStatusOk,
			AgentVersion:         &version,
		}); err != nil {
			t.Fatalf("UpsertServerHealth(%d): %v", peers, err)
		}
	}
	upsert(3, agent)
	upsert(5, "0.2.0")

	var count int
	if err := pool(t).QueryRow(ctx,
		`SELECT count(*) FROM server_health WHERE server_id = $1`, f.server.ID).Scan(&count); err != nil {
		t.Fatalf("подсчёт строк health: %v", err)
	}
	if count != 1 {
		t.Fatalf("строк health %d, ожидалось 1: узел = одна строка наблюдаемого состояния", count)
	}
	got, err := q.ServerHealthOf(ctx, f.server.ID)
	if err != nil {
		t.Fatalf("ServerHealthOf: %v", err)
	}
	if got.PeersConfigured != 5 || got.PeersHandshaked != 4 {
		t.Errorf("повторный heartbeat не заменил пиеров: %+v", got)
	}
	if got.AgentVersion == nil || *got.AgentVersion != "0.2.0" {
		t.Errorf("agent_version = %v, ожидалось 0.2.0", got.AgentVersion)
	}
	if got.AgentUptimeSec != nil {
		t.Errorf("agent_uptime_sec заполнен без значения в сообщении: %v", *got.AgentUptimeSec)
	}
}

func TestUpsertDeviceDayTrafficSums(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := db.New(pool(t))
	f := newNetFixture(t, ctx, "10.99.9.0/24")

	// Агрегат смотрит на пару (пользователь, устройство): профиль для него не нужен.
	now := time.Now().UTC()
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	for _, rx := range []int64{100, 250} {
		if err := q.UpsertDeviceDayTraffic(ctx, db.UpsertDeviceDayTrafficParams{
			UserID: f.user, DeviceID: f.device, Day: day, RxBytes: rx, TxBytes: rx / 2,
		}); err != nil {
			t.Fatalf("UpsertDeviceDayTraffic(%d): %v", rx, err)
		}
	}
	var gotRx, gotTx int64
	if err := pool(t).QueryRow(ctx, `SELECT rx_bytes, tx_bytes FROM device_day_traffic
	    WHERE user_id = $1 AND device_id = $2 AND day = $3`,
		f.user, f.device, day).Scan(&gotRx, &gotTx); err != nil {
		t.Fatalf("чтение агрегата: %v", err)
	}
	// Сложение приростов, а не запись абсолютного счётчика (ADR-006).
	if gotRx != 350 || gotTx != 175 {
		t.Errorf("агрегат = (%d, %d), ожидалось (350, 175)", gotRx, gotTx)
	}
}

func TestMarkStaleHealthReturnsServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := db.New(pool(t))
	f := newNetFixture(t, ctx, "10.99.10.0/24")

	// Три интервала heartbeat по 30 с (§4.3): 200 с молчания уже за порогом.
	if err := q.UpsertServerHealth(ctx, db.UpsertServerHealthParams{
		ServerID:             f.server.ID,
		ObservedAt:           time.Now().Add(-200 * time.Second),
		PeersConfigured:      1,
		PeersHandshaked:      1,
		AppliedConfigVersion: 3,
		Status:               db.HealthStatusOk,
	}); err != nil {
		t.Fatalf("UpsertServerHealth: %v", err)
	}
	// Условие выбора — status='ok', поэтому переход occurs ровно один раз: второе
	// окно не породит второе событие node_stale. Единственная ok-строка старше
	// порога в фикстуре — наша; тест это и проверяет числом.
	ids, err := q.MarkStaleHealth(ctx)
	if err != nil {
		t.Fatalf("MarkStaleHealth: %v", err)
	}
	if len(ids) != 1 || ids[0] != f.server.ID {
		t.Fatalf("переход ok->stale отдал %v, ожидался [%v]", ids, f.server.ID)
	}
	got, err := q.ServerHealthOf(ctx, f.server.ID)
	if err != nil {
		t.Fatalf("ServerHealthOf: %v", err)
	}
	if got.Status != db.HealthStatusStale {
		t.Errorf("статус остался %q", got.Status)
	}
	again, err := q.MarkStaleHealth(ctx)
	if err != nil {
		t.Fatalf("повторный MarkStaleHealth: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("повторный проход отдал %v, ожидался ноль: событие задублировалось бы", again)
	}
}

func TestMigration0006UpDownUp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	url := databaseURL(t)

	// Схема пересоздаётся: prepared-стейтменты общего пула устаревают, пул
	// инвалидируется и следующий тест построит новый (тот же путь, что A-1).
	t.Cleanup(func() {
		if sharedPool != nil {
			sharedPool.Close()
			sharedPool = nil
		}
	})

	if _, err := migrate.Steps(ctx, url, -1<<31); err != nil {
		t.Fatalf("down all: %v", err)
	}
	v, err := migrate.Up(ctx, url)
	if err != nil {
		t.Fatalf("первый up: %v", err)
	}
	if want := latestMigration(t); v != want {
		t.Errorf("после up версия %d, ожидалось %d: набор миграций применился не полностью", v, want)
	}
	v2, err := migrate.Up(ctx, url)
	if err != nil || v2 != v {
		t.Errorf("no-op up: версия %d->%d err=%v", v, v2, err)
	}

	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)
	// Откат 0006 пересобирает enum, поэтому проверка после повторного up — это
	// проверка обеих половин файла, а не только up.
	for _, col := range []string{"agent_version", "agent_uptime_sec"} {
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		        WHERE table_schema='public' AND table_name='server_health' AND column_name=$1)`,
			col).Scan(&exists); err != nil || !exists {
			t.Errorf("колонка server_health.%s после up: exists=%v err=%v", col, exists, err)
		}
	}
	var actions []string
	rows, err := conn.Query(ctx, `SELECT e.enumlabel FROM pg_enum e
	    JOIN pg_type t ON t.oid = e.enumtypid WHERE t.typname = 'audit_action'`)
	if err != nil {
		t.Fatalf("чтение audit_action: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("scan enum: %v", err)
		}
		actions = append(actions, s)
	}
	for _, want := range []string{"bootstrap_token_issued", "bootstrap_token_revoked", "server_deleted"} {
		var found bool
		for _, a := range actions {
			if a == want {
				found = true
			}
		}
		if !found {
			t.Errorf("значения %q нет в audit_action (%v): 0006 применена не полностью", want, actions)
		}
	}
}

// TestNumericFieldsReadAsStrings закрывает вторую половину override'а numeric:
// запись строкой работает уже в seedLocation, а вот чтение numeric в string
// (load1/cpu_pct в задаче 10, lat/lon в задаче 2) — тот путь, на котором
// pgtype-обёртка или отказ кодирования проявились бы только в проде.
func TestNumericFieldsReadAsStrings(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := db.New(pool(t))
	f := newNetFixture(t, ctx, "10.99.11.0/24")

	load1, cpuPct := "1.250", "12.50"
	if err := q.UpsertServerHealth(ctx, db.UpsertServerHealthParams{
		ServerID:             f.server.ID,
		ObservedAt:           time.Now(),
		PeersConfigured:      2,
		PeersHandshaked:      2,
		Load1:                &load1,
		CpuPct:               &cpuPct,
		AppliedConfigVersion: 1,
		Status:               db.HealthStatusOk,
	}); err != nil {
		t.Fatalf("UpsertServerHealth с load1/cpu_pct: %v", err)
	}
	got, err := q.ServerHealthOf(ctx, f.server.ID)
	if err != nil {
		t.Fatalf("ServerHealthOf: %v", err)
	}
	// Точность фикстуры обязана дойти нетронутой: numeric(6,3) отдаёт "1.250",
	// а не "1.25" или "1.2500000" — сравнение значений в задаче 10 держится на этом.
	if got.Load1 == nil || *got.Load1 != load1 {
		t.Errorf("load1 = %v, ожидалось %q", got.Load1, load1)
	}
	if got.CpuPct == nil || *got.CpuPct != cpuPct {
		t.Errorf("cpu_pct = %v, ожидалось %q", got.CpuPct, cpuPct)
	}
}

// TestArrayParamsMatchRows вызывает запросы с массивным параметром вживую: без
// каста `::uuid[]` генератор отдаёт скалярный *uuid.UUID, и эта подмена типов
// обнаружилась бы только на первом боевом проходе задачи 4 или 9.
func TestArrayParamsMatchRows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := db.New(pool(t))
	f := newNetFixture(t, ctx, "10.99.12.0/24")
	d2 := addDevice(t, ctx, q, f.user, 1)
	other := addDevice(t, ctx, q, f.user, 2)

	p1 := seedProfile(t, ctx, q, f.device, f.server.ID, "10.99.12.1", time.Hour)
	p2 := seedProfile(t, ctx, q, d2, f.server.ID, "10.99.12.2", time.Hour)
	for _, c := range []struct {
		addr    string
		profile uuid.UUID
	}{{"10.99.12.1", p1.ID}, {"10.99.12.2", p2.ID}} {
		if err := claimAddr(q, ctx, f.server.ID, c.addr, c.profile); err != nil {
			t.Fatalf("claim %s: %v", c.addr, err)
		}
	}

	// DevicesByPublicKeys: два известных ключа + один несуществующий. Отсутствующий
	// обязан молча не вернуться, а не уронить вызов: узел показывает пиеров, которых
	// control plane уже не знает.
	unknown := keyFromSeed("no-such-device")
	rows, err := q.DevicesByPublicKeys(ctx, []string{
		seededKey(t, ctx, q, f.device), seededKey(t, ctx, q, d2), unknown})
	if err != nil {
		t.Fatalf("DevicesByPublicKeys: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("по ключам вернулось %d строк, ожидалось 2", len(rows))
	}

	// ReleaseAddressesByProfiles одним вызовом освобождает оба назначения.
	if err := q.ReleaseAddressesByProfiles(ctx, []uuid.UUID{p1.ID, p2.ID}); err != nil {
		t.Fatalf("ReleaseAddressesByProfiles: %v", err)
	}
	for _, id := range []uuid.UUID{p1.ID, p2.ID} {
		if _, err := q.AddressOfProfile(ctx, &id); !errors.Is(err, pgx.ErrNoRows) {
			t.Errorf("профиль %v после освобождения держит адрес: err=%v", id, err)
		}
	}

	// HandshakedDevicesAfter: событие есть только у d2, и только в окне.
	if err := q.InsertConnectionEvent(ctx, db.InsertConnectionEventParams{
		UserID: &f.user, DeviceID: &d2, ServerID: &f.server.ID,
		Event: db.EventTypeHandshakeObserved, Detail: []byte(`{}`),
	}); err != nil {
		t.Fatalf("InsertConnectionEvent: %v", err)
	}
	seen, err := q.HandshakedDevicesAfter(ctx, db.HandshakedDevicesAfterParams{
		ServerID:  &f.server.ID,
		CreatedAt: time.Now().Add(-time.Minute),
		Column3:   []uuid.UUID{f.device, d2, other},
	})
	if err != nil {
		t.Fatalf("HandshakedDevicesAfter: %v", err)
	}
	// device_id в connection_events nullable (событие может быть о сервере, а не о
	// пиере), поэтому выборка приходит []*uuid.UUID и пустой указатель здесь — не
	// «устройство-ноль», а «событие без устройства»: его в окне быть не должно.
	if len(seen) != 1 || seen[0] == nil || *seen[0] != d2 {
		t.Fatalf("handshake наблюдался у %v, ожидался единственный %v", seen, d2)
	}
}

// seededKey отдаёт публичный ключ устройства — он нужен там, где запрос принимает
// массив ключей, а фикстура знает только id.
func seededKey(t *testing.T, ctx context.Context, q *db.Queries, id uuid.UUID) string {
	t.Helper()
	d, err := q.DeviceByID(ctx, id)
	if err != nil {
		t.Fatalf("DeviceByID(%v): %v", id, err)
	}
	return d.PublicKey
}

func TestAuditActionNewValuesExist(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := db.New(pool(t))

	adminID := uuid.New()
	hash, err := auth.HashPassword("integration-admin-123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if _, err := q.InsertAdminUser(ctx, db.InsertAdminUserParams{
		ID: adminID, Email: "audit-" + adminID.String()[:8] + "@novavpn.test", PasswordHash: hash,
	}); err != nil {
		t.Fatalf("InsertAdminUser: %v", err)
	}
	// Ряды удаляются: down 0006 пересобирает enum через USING-каст, и запись с новым
	// значением отката не переживёт — она уронила бы TestMigrationsUpToDownToUp
	// в следующем прогоне. Именно этот отказ и описан в комментарии к файлу отката.
	t.Cleanup(func() {
		if _, err := pool(t).Exec(context.Background(),
			`DELETE FROM admin_audit_logs WHERE admin_id = $1`, adminID); err != nil {
			t.Errorf("очистка аудита: %v", err)
		}
	})

	for _, action := range []db.AuditAction{
		db.AuditActionServerDeleted, db.AuditActionBootstrapTokenIssued,
		db.AuditActionBootstrapTokenRevoked,
	} {
		if err := q.InsertAdminAudit(ctx, db.InsertAdminAuditParams{
			AdminID: &adminID, Action: action, TargetType: "server",
			TargetID: uuid.New().String(), Reason: "проверка значений enum 0006",
			RequestID: "req-" + string(action),
		}); err != nil {
			t.Fatalf("InsertAdminAudit(%s): %v", action, err)
		}
	}
	// Причина обязательна и не может быть короче нижней границы констрейнта схемы, а
	// не правила кода: проверяем, что отказ действительно приходит из БД.
	if err := q.InsertAdminAudit(ctx, db.InsertAdminAuditParams{
		AdminID: &adminID, Action: db.AuditActionServerDeleted, TargetType: "server",
		TargetID: uuid.New().String(), Reason: "нк", RequestID: "req-short",
	}); err == nil {
		t.Error("аудит с причиной из двух символов принят")
	}
}
