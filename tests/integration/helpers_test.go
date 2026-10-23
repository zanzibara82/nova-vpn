//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/db"
)

// Один пул на весь прогон: интеграционные тесты их создают десятки, а
// pg_max_connections на dev-стеке конечен.
var sharedPool *pgxpool.Pool

func pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if sharedPool == nil {
		p, err := db.Pool(context.Background(), databaseURL(t))
		if err != nil {
			t.Fatalf("pool: %v", err)
		}
		sharedPool = p
	}
	return sharedPool
}

func bytes32ForTests() []byte { return []byte("integration-secret-0000000000000000") }

func redisClient(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("NOVAVPN_REDIS_ADDR")
	if addr == "" {
		t.Skip("NOVAVPN_REDIS_ADDR is not set; run `make up-dev` first")
	}
	c := redis.NewClient(&redis.Options{Addr: addr})
	if err := c.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("redis at %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func seedUser(t *testing.T, ctx context.Context, q *db.Queries, withPlan bool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	hash, err := auth.HashPassword("integration-password-123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if _, err := q.InsertUser(ctx, db.InsertUserParams{
		ID: id, Email: "seed-" + id.String()[:8] + "@novavpn.test",
		PasswordHash: hash, Locale: "ru",
	}); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if withPlan {
		if _, err := q.InsertSubscription(ctx, db.InsertSubscriptionParams{
			ID:       uuid.New(),
			UserID:   id,
			PlanID:   uuid.MustParse("00000000-0000-4000-8000-000000000a01"),
			StartsAt: time.Now(),
		}); err != nil {
			t.Fatalf("InsertSubscription: %v", err)
		}
	}
	return id
}

func seedUserWithoutPlan(t *testing.T, ctx context.Context, q *db.Queries) uuid.UUID {
	return seedUser(t, ctx, q, false)
}

func seedUserWithPlan(t *testing.T, ctx context.Context, q *db.Queries, slug string) uuid.UUID {
	t.Helper()
	id := seedUser(t, ctx, q, false)
	planID, err := q.PlanIDBySlug(ctx, slug)
	if err != nil {
		t.Fatalf("PlanIDBySlug: %v", err)
	}
	if _, err := q.InsertSubscription(ctx, db.InsertSubscriptionParams{
		ID:       uuid.New(),
		UserID:   id,
		PlanID:   planID,
		StartsAt: time.Now(),
	}); err != nil {
		t.Fatalf("InsertSubscription: %v", err)
	}
	return id
}

// keyFromSeed собирает публичный ключ WireGuard из произвольной строки. Форму
// берём из sha256, а не из счётчика: ключ в схеме UNIQUE глобально, и «i-й по
// счёту» ключ столкнулся бы с рядом того же теста на следующем прогоне.
// Младшие два бита последнего байта обнулены — в канонической base64 они spare,
// и без этого ключ был бы неканоническим ровно тем вариантом, из-за которого в
// внутреннем модуле devices существует ValidateKey.
func keyFromSeed(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	sum[31] &= 0xFC
	return base64.StdEncoding.EncodeToString(sum[:])
}

func seedLocation(t *testing.T, ctx context.Context, q *db.Queries) uuid.UUID {
	t.Helper()
	id := uuid.New()
	// Город несёт суффикс id: UNIQUE (country_code, city, lat, lon) из 0002, а dev-база
	// между прогонами одна и та же — одинаковый Berlin второй раз упёрся бы в коллизию.
	// lat/lon — строки: тип после override'а numeric из задачи 1.
	loc, err := q.InsertServerLocation(ctx, db.InsertServerLocationParams{
		ID: id, CountryCode: "DE", City: "berlin-" + id.String()[:8],
		Lat: "52.5200", Lon: "13.4050", Timezone: "Europe/Berlin",
	})
	if err != nil {
		t.Fatalf("InsertServerLocation: %v", err)
	}
	return loc.ID
}

// seedServer создаёт сервер с maintenance_status='maintenance' (дефолт схемы):
// «зарегистрирован» ≠ «работает», и перевод в online — отдельный явный шаг теста
// (setServerOnline), иначе каталог задачи 2 молча тестировался бы на полуготовой фикстуре.
func seedServer(t *testing.T, ctx context.Context, q *db.Queries, poolV4 string) db.VpnServer {
	t.Helper()
	id := uuid.New()
	srv, err := q.InsertServer(ctx, db.InsertServerParams{
		ID: id, LocationID: seedLocation(t, ctx, q),
		Name: "srv-" + id.String()[:8],
		// TEST-NET-3 (203.0.113.0/24) — адресная база, зарезервированная для документации
		// и примеров: реальный хост сюда попасть не может.
		AdvertisedHost: fmt.Sprintf("203.0.113.%d", int(id[15])%254+1),
		ListenPort:     51820 + int32(id[14])%1000,
		PublicKey:      keyFromSeed("server-" + id.String()),
		AddressPoolV4:  netip.MustParsePrefix(poolV4),
		Mtu:            1420, KeepaliveSec: 25,
		Provider: "integration",
	})
	if err != nil {
		t.Fatalf("InsertServer: %v", err)
	}
	return srv
}

func setServerOnline(t *testing.T, ctx context.Context, q *db.Queries, id uuid.UUID) {
	t.Helper()
	row, err := q.SetServerMaintenance(ctx, db.SetServerMaintenanceParams{
		ID: id, MaintenanceStatus: db.MaintenanceStatusOnline,
	})
	if err != nil {
		t.Fatalf("SetServerMaintenance(online): %v", err)
	}
	if row.MaintenanceStatus != db.MaintenanceStatusOnline {
		t.Fatalf("setServerOnline: статус остался %q", row.MaintenanceStatus)
	}
}

// seedProfile вставляет профиль через InsertProfile, то есть ровно так, как это делает
// выдача (задача 5): статус и peer_state здесь 'active', а другие статусы фикстуре
// задают явными запросами (SupersedeProfile/RevokeProfile/MarkProfileExpired), иначе
// тест проверял бы быстрое INSERT'ом состояние, которого выдача не производит.
// expiresIn обязан быть положительным: profiles_window требует expires_at > issued_at.
func seedProfile(t *testing.T, ctx context.Context, q *db.Queries, deviceID, serverID uuid.UUID,
	addr string, expiresIn time.Duration) db.VpnProfile {
	t.Helper()
	p, err := q.InsertProfile(ctx, db.InsertProfileParams{
		ID: uuid.New(), DeviceID: deviceID, ServerID: serverID,
		AddressV4: netip.MustParseAddr(addr),
		ExpiresAt: time.Now().Add(expiresIn),
	})
	if err != nil {
		t.Fatalf("InsertProfile: %v", err)
	}
	return p
}

func seedDevice(t *testing.T, ctx context.Context, q *db.Queries, user uuid.UUID, i int) db.Device {
	t.Helper()
	d, err := q.InsertDevice(ctx, db.InsertDeviceParams{
		ID: uuid.New(), UserID: user,
		PublicKey: keyFromSeed("device-" + user.String() + "-" + strconv.Itoa(i)),
		Platform:  db.DevicePlatformLinux, Name: "dev",
	})
	if err != nil {
		t.Fatalf("InsertDevice: %v", err)
	}
	return d
}
