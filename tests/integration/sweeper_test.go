//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/novavpn/novavpn/internal/connections"
	"github.com/novavpn/novavpn/internal/db"
)

type sweepFixture struct {
	pool   *pgxpool.Pool
	q      *db.Queries
	store  connections.Store
	user   uuid.UUID
	device uuid.UUID
	server db.VpnServer
}

func newSweepFixture(t *testing.T) *sweepFixture {
	t.Helper()
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	f := &sweepFixture{
		pool: p, q: q, store: connections.NewStore(p),
		user: seedUserWithPlan(t, ctx, q, "internal-default"),
	}
	f.device = seedDevice(t, ctx, q, f.user, 0).ID
	f.server = seedServer(t, ctx, q, "10.97.70.0/29")
	setServerOnline(t, ctx, q, f.server.ID)
	return f
}

// expireProfile двигает оба конца окна: constraint profiles_window требует
// expires_at > issued_at, поэтому «истёкший» профиль — это не только прошлый
// expires_at, но и ещё более прошлый issued_at.
func expireProfile(t *testing.T, p *pgxpool.Pool, id uuid.UUID) {
	t.Helper()
	if _, err := p.Exec(context.Background(),
		`UPDATE vpn_profiles SET issued_at = now() - interval '2 hours',
		        expires_at = now() - interval '1 minute' WHERE id = $1`, id); err != nil {
		t.Fatalf("протухание профиля %v: %v", id, err)
	}
}

func profileStatus(t *testing.T, p *pgxpool.Pool, id uuid.UUID) (string, *time.Time) {
	t.Helper()
	var status string
	var revokedAt *time.Time
	if err := p.QueryRow(context.Background(),
		"SELECT status, revoked_at FROM vpn_profiles WHERE id = $1", id).
		Scan(&status, &revokedAt); err != nil {
		t.Fatalf("статус профиля %v: %v", id, err)
	}
	return status, revokedAt
}

func countEvents(t *testing.T, p *pgxpool.Pool, deviceID uuid.UUID, event string) int {
	t.Helper()
	var n int
	if err := p.QueryRow(context.Background(),
		"SELECT count(*) FROM connection_events WHERE device_id = $1 AND event = $2",
		deviceID, event).Scan(&n); err != nil {
		t.Fatalf("события %q устройства %v: %v", event, deviceID, err)
	}
	return n
}

func addressReleased(t *testing.T, p *pgxpool.Pool, serverID uuid.UUID, addr netip.Addr) *time.Time {
	t.Helper()
	var allocated *uuid.UUID
	var reusable *time.Time
	if err := p.QueryRow(context.Background(),
		"SELECT allocated_to, reusable_at FROM tunnel_addresses WHERE server_id = $1 AND address = $2",
		serverID, addr.String()).Scan(&allocated, &reusable); err != nil {
		t.Fatalf("строка адреса %v: %v", addr, err)
	}
	if allocated != nil {
		t.Errorf("адрес %v всё ещё закреплён за %v", addr, allocated)
	}
	if reusable == nil {
		t.Errorf("у адреса %v не открыто окно переиспользования", addr)
	}
	return reusable
}

func TestSweepExpiredMarksReleasesAndBumpsOnce(t *testing.T) {
	f := newSweepFixture(t)
	ctx := context.Background()
	// База общая с другими тестами: сначала добираем чужие просроченные профили,
	// иначе точный счётчик ниже мерил бы не нашу фикстуру.
	if _, err := f.store.SweepExpired(ctx, time.Now()); err != nil {
		t.Fatalf("осушающий SweepExpired: %v", err)
	}
	prof := profileOf(t, f.user, f.device, f.server.ID)
	expireProfile(t, f.pool, prof.ID)
	versionBefore := serverVersion(t, f.server.ID)

	n, err := f.store.SweepExpired(ctx, time.Now())
	if err != nil {
		t.Fatalf("SweepExpired: %v", err)
	}
	if n != 1 {
		t.Fatalf("SweepExpired = %d, want 1", n)
	}
	if status, _ := profileStatus(t, f.pool, prof.ID); status != "expired" {
		t.Errorf("статус профиля = %q, want expired", status)
	}
	reusable := addressReleased(t, f.pool, f.server.ID, prof.AddressV4)
	// Окно переиспользования задаёт SQL задачи 1: пять минут. Проверяем сам факт окна
	// и его порядок, а не секундную точность чужого now().
	if d := time.Until(*reusable); d < 4*time.Minute || d > 6*time.Minute {
		t.Errorf("окно переиспользования = %v, want около 5 минут", d)
	}
	if got := serverVersion(t, f.server.ID); got != versionBefore+1 {
		t.Errorf("config_version = %d, want %d", got, versionBefore+1)
	}
	if n := countEvents(t, f.pool, f.device, "profile_expired"); n != 1 {
		t.Errorf("событий profile_expired = %d, want 1", n)
	}
	var eventUser *uuid.UUID
	if err := f.pool.QueryRow(ctx,
		`SELECT user_id FROM connection_events WHERE device_id = $1 AND event = 'profile_expired'`,
		f.device).Scan(&eventUser); err != nil {
		t.Fatalf("пользователь события просрочки: %v", err)
	}
	if eventUser == nil || *eventUser != f.user {
		t.Errorf("user_id события = %v, want %v", eventUser, f.user)
	}

	// Повторный проход: профиль уже expired, событий и bump'ов быть не должно.
	n, err = f.store.SweepExpired(ctx, time.Now())
	if err != nil {
		t.Fatalf("повторный SweepExpired: %v", err)
	}
	if n != 0 {
		t.Errorf("повторный SweepExpired = %d, want 0", n)
	}
	if got := serverVersion(t, f.server.ID); got != versionBefore+1 {
		t.Errorf("повторный проход поднял config_version до %d, want %d", got, versionBefore+1)
	}
	if n := countEvents(t, f.pool, f.device, "profile_expired"); n != 1 {
		t.Errorf("после повтора событий profile_expired = %d, want 1", n)
	}
}

func TestSweepDormantRevokesOnlyForgottenProfiles(t *testing.T) {
	f := newSweepFixture(t)
	ctx := context.Background()
	// Чужие спящие профили прошлых прогонов не должны попасть в точный счётчик.
	if _, err := f.store.SweepDormant(ctx, time.Now()); err != nil {
		t.Fatalf("осушающий SweepDormant: %v", err)
	}
	silentDev := seedDevice(t, ctx, f.q, f.user, 1).ID
	seenDev := seedDevice(t, ctx, f.q, f.user, 2).ID
	youngDev := seedDevice(t, ctx, f.q, f.user, 3).ID
	silent := profileOf(t, f.user, silentDev, f.server.ID)
	seen := profileOf(t, f.user, seenDev, f.server.ID)
	young := profileOf(t, f.user, youngDev, f.server.ID)
	for _, id := range []uuid.UUID{silent.ID, seen.ID} {
		if _, err := f.pool.Exec(ctx,
			"UPDATE vpn_profiles SET issued_at = now() - interval '8 days' WHERE id = $1", id); err != nil {
			t.Fatalf("состаривание профиля %v: %v", id, err)
		}
	}
	if _, err := f.pool.Exec(ctx,
		"UPDATE vpn_profiles SET issued_at = now() - interval '2 days' WHERE id = $1", young.ID); err != nil {
		t.Fatalf("омоложение профиля %v: %v", young.ID, err)
	}
	// Соединение было: это клиент, который спит, а не «выдал и забыл».
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO connection_events (user_id, device_id, server_id, event, detail)
		 VALUES ($1, $2, $3, 'handshake_observed', '{}')`, f.user, seenDev, f.server.ID); err != nil {
		t.Fatalf("handshake-событие: %v", err)
	}

	n, err := f.store.SweepDormant(ctx, time.Now())
	if err != nil {
		t.Fatalf("SweepDormant: %v", err)
	}
	if n != 1 {
		t.Fatalf("SweepDormant = %d, want 1", n)
	}
	status, revokedAt := profileStatus(t, f.pool, silent.ID)
	if status != "revoked" || revokedAt == nil {
		t.Errorf("спящий профиль: status = %q, revoked_at = %v, want revoked и отметку", status, revokedAt)
	}
	addressReleased(t, f.pool, f.server.ID, silent.AddressV4)
	if n := countEvents(t, f.pool, silentDev, "profile_revoked"); n != 1 {
		t.Errorf("событий profile_revoked = %d, want 1", n)
	}
	var reason string
	if err := f.pool.QueryRow(ctx,
		`SELECT detail->>'reason' FROM connection_events
		  WHERE device_id = $1 AND event = 'profile_revoked'`, silentDev).Scan(&reason); err != nil {
		t.Fatalf("причина отзыва: %v", err)
	}
	if reason != "dormant" {
		t.Errorf("причина отзыва = %q, want dormant", reason)
	}
	for _, id := range []uuid.UUID{seen.ID, young.ID} {
		if status, _ := profileStatus(t, f.pool, id); status != "active" {
			t.Errorf("профиль %v: status = %q, want active", id, status)
		}
	}

	// Повтор: спящих больше нет, seen и young не подпадают под порог.
	n, err = f.store.SweepDormant(ctx, time.Now())
	if err != nil {
		t.Fatalf("повторный SweepDormant: %v", err)
	}
	if n != 0 {
		t.Errorf("повторный SweepDormant = %d, want 0", n)
	}
}

func TestSweepStaleMarksOnceAndWritesEvent(t *testing.T) {
	f := newSweepFixture(t)
	ctx := context.Background()
	seedHealth(t, ctx, f.q, f.server.ID, db.HealthStatusOk, time.Now().Add(-200*time.Second))

	n, err := f.store.SweepStale(ctx, time.Now())
	if err != nil {
		t.Fatalf("SweepStale: %v", err)
	}
	// В общей dev-базе могли остаться другие зависшие узлы прошлых прогонов: важно,
	// что наш узел помечен, а не что он единственный в базе.
	if n < 1 {
		t.Fatalf("SweepStale = %d, want >= 1", n)
	}
	var status db.HealthStatus
	if err := f.pool.QueryRow(ctx,
		"SELECT status FROM server_health WHERE server_id = $1", f.server.ID).Scan(&status); err != nil {
		t.Fatalf("статус health: %v", err)
	}
	if status != db.HealthStatusStale {
		t.Errorf("health узла = %q, want stale", status)
	}
	if n := nodeStaleEvents(t, f.pool, f.server.ID); n != 1 {
		t.Errorf("событий node_stale узла = %d, want 1", n)
	}

	// Повтор не должен писать второе событие: условие status = 'ok' живёт в SQL.
	n, err = f.store.SweepStale(ctx, time.Now())
	if err != nil {
		t.Fatalf("повторный SweepStale: %v", err)
	}
	if n != 0 {
		t.Errorf("повторный SweepStale = %d, want 0", n)
	}
	if n := nodeStaleEvents(t, f.pool, f.server.ID); n != 1 {
		t.Errorf("после повтора событий node_stale = %d, want 1", n)
	}
}

func nodeStaleEvents(t *testing.T, p *pgxpool.Pool, serverID uuid.UUID) int {
	t.Helper()
	var n int
	if err := p.QueryRow(context.Background(),
		"SELECT count(*) FROM connection_events WHERE server_id = $1 AND event = 'node_stale'",
		serverID).Scan(&n); err != nil {
		t.Fatalf("события node_stale узла %v: %v", serverID, err)
	}
	return n
}

func TestSweepRetentionCleansThreeIndependentTables(t *testing.T) {
	f := newSweepFixture(t)
	ctx := context.Background()
	hash := sha256.Sum256([]byte(uuid.NewString()))

	var oldEvent, youngEvent int64
	if err := f.pool.QueryRow(ctx,
		`INSERT INTO connection_events (user_id, event, detail, created_at)
		 VALUES ($1, 'profile_issued', '{}', now() - interval '91 days') RETURNING id`,
		f.user).Scan(&oldEvent); err != nil {
		t.Fatalf("старое событие: %v", err)
	}
	if err := f.pool.QueryRow(ctx,
		`INSERT INTO connection_events (user_id, event, detail)
		 VALUES ($1, 'profile_issued', '{}') RETURNING id`, f.user).Scan(&youngEvent); err != nil {
		t.Fatalf("молодое событие: %v", err)
	}

	family := uuid.New()
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO refresh_token_families
		        (id, user_id, current_token_hash, issued_at, last_used_at, expires_at, ip)
		 VALUES ($1, $2, $3, now() - interval '91 days', now() - interval '91 days',
		         now() + interval '1 day', '198.51.100.7')`,
		family, f.user, hash[:]); err != nil {
		t.Fatalf("старая refresh-семья: %v", err)
	}

	completedOld, abandonedOld, completedFresh := uuid.New(), uuid.New(), uuid.New()
	for _, row := range []struct {
		id         uuid.UUID
		createdAgo string
		completed  string
	}{
		{completedOld, "26 hours", "25 hours"},
		{abandonedOld, "8 days", ""},
		{completedFresh, "1 hour", "30 minutes"},
	} {
		var err error
		if row.completed == "" {
			_, err = f.pool.Exec(ctx,
				`INSERT INTO idempotency_keys
				        (id, user_id, route, idem_key, request_hash, created_at)
				 VALUES ($1, $2, '/api/v1/auth/login', $3, $4, now() - $5::interval)`,
				row.id, f.user, row.id.String(), hash[:], row.createdAgo)
		} else {
			_, err = f.pool.Exec(ctx,
				`INSERT INTO idempotency_keys
				        (id, user_id, route, idem_key, request_hash, response_status, response_body,
				         created_at, completed_at)
				 VALUES ($1, $2, '/api/v1/auth/login', $3, $4, 200, '{}',
				         now() - $5::interval, now() - $6::interval)`,
				row.id, f.user, row.id.String(), hash[:], row.createdAgo, row.completed)
		}
		if err != nil {
			t.Fatalf("ключ идемпотентности %v: %v", row.id, err)
		}
	}

	ret, err := f.store.SweepRetention(ctx, time.Now())
	if err != nil {
		t.Fatalf("SweepRetention: %v", err)
	}
	if ret.EventsDeleted < 1 || ret.IPsCleared < 1 || ret.KeysPurged < 2 {
		t.Errorf("Retention = %+v, want events>=1, ips>=1, keys>=2", ret)
	}
	var exists bool
	if err := f.pool.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM connection_events WHERE id = $1)", oldEvent).Scan(&exists); err != nil {
		t.Fatalf("старое событие после retention: %v", err)
	}
	if exists {
		t.Errorf("событие %d старше 90 суток не удалено", oldEvent)
	}
	if err := f.pool.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM connection_events WHERE id = $1)", youngEvent).Scan(&exists); err != nil {
		t.Fatalf("молодое событие после retention: %v", err)
	}
	if !exists {
		t.Errorf("молодое событие %d удалено вместе со старыми", youngEvent)
	}

	var ip *string
	if err := f.pool.QueryRow(ctx,
		"SELECT ip::text FROM refresh_token_families WHERE id = $1", family).Scan(&ip); err != nil {
		t.Fatalf("refresh-семья %v удалена, а retention обязан оставить её для детекта переиспользования: %v",
			family, err)
	}
	if ip != nil {
		t.Errorf("ip семьи = %q, want NULL", *ip)
	}

	for _, row := range []struct {
		id   uuid.UUID
		want bool
	}{
		{completedOld, false},
		{abandonedOld, false},
		{completedFresh, true},
	} {
		if err := f.pool.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM idempotency_keys WHERE id = $1)", row.id).Scan(&exists); err != nil {
			t.Fatalf("ключ %v после retention: %v", row.id, err)
		}
		if exists != row.want {
			t.Errorf("ключ %v существует = %v, want %v", row.id, exists, row.want)
		}
	}
}

func TestSweepExpiredConcurrentMarksOnce(t *testing.T) {
	f := newSweepFixture(t)
	ctx := context.Background()
	if _, err := f.store.SweepExpired(ctx, time.Now()); err != nil {
		t.Fatalf("осушающий SweepExpired: %v", err)
	}
	prof := profileOf(t, f.user, f.device, f.server.ID)
	expireProfile(t, f.pool, prof.ID)

	var wg sync.WaitGroup
	counts := make([]int, 2)
	errs := make([]error, 2)
	for i := range counts {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			counts[i], errs[i] = f.store.SweepExpired(ctx, time.Now())
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("горутина %d: %v", i, err)
		}
	}
	if sum := counts[0] + counts[1]; sum != 1 {
		t.Errorf("суммарно помечено = %d (%v), want 1: условие статуса обязано отсечь вторую транзакцию",
			sum, counts)
	}
	if n := countEvents(t, f.pool, f.device, "profile_expired"); n != 1 {
		t.Errorf("событий profile_expired = %d, want 1", n)
	}
}

// syncBuffer — журнал, который читает тест и пишет горутина метлы одновременно.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestRunSweepsAllKindsAndLogsOneLine проверяет сборку Report через наблюдаемый
// контракт Run: sweepAll не экспортируется, а журнал несёт все четыре числа.
func TestRunSweepsAllKindsAndLogsOneLine(t *testing.T) {
	f := newSweepFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	profExpired := profileOf(t, f.user, f.device, f.server.ID)
	expireProfile(t, f.pool, profExpired.ID)
	dormantDev := seedDevice(t, context.Background(), f.q, f.user, 1).ID
	profDormant := profileOf(t, f.user, dormantDev, f.server.ID)
	if _, err := f.pool.Exec(context.Background(),
		"UPDATE vpn_profiles SET issued_at = now() - interval '8 days' WHERE id = $1",
		profDormant.ID); err != nil {
		t.Fatalf("состаривание спящего профиля: %v", err)
	}
	seedHealth(t, context.Background(), f.q, f.server.ID, db.HealthStatusOk,
		time.Now().Add(-200*time.Second))
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO connection_events (user_id, event, detail, created_at)
		 VALUES ($1, 'profile_issued', '{}', now() - interval '91 days')`, f.user); err != nil {
		t.Fatalf("старое событие для retention: %v", err)
	}

	var buf syncBuffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	done := make(chan struct{})
	go func() {
		connections.Run(ctx, f.store, log, 24*time.Hour)
		close(done)
	}()

	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(buf.String(), `"msg":"sweep"`) {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("первый проход метлы не записал строку sweep: %s", buf.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done

	var sweep map[string]any
	for _, line := range strings.Split(buf.String(), "\n") {
		if !strings.Contains(line, `"msg":"sweep"`) {
			continue
		}
		if sweep != nil {
			t.Fatalf("строк sweep больше одной: %s", buf.String())
		}
		if err := json.Unmarshal([]byte(line), &sweep); err != nil {
			t.Fatalf("разбор строки sweep: %v", err)
		}
	}
	if sweep == nil {
		t.Fatal("строка sweep не найдена")
	}
	for _, k := range []string{"expired", "dormant", "stale", "events_deleted"} {
		v, ok := sweep[k].(float64)
		if !ok || v < 1 {
			t.Errorf("sweep[%q] = %v, want >= 1 (%v)", k, sweep[k], sweep)
		}
	}
}
