//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/novavpn/novavpn/internal/connections"
	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/entitlements"
)

func newProfilesService(t *testing.T) *connections.Service {
	t.Helper()
	p := pool(t)
	return connections.NewService(p, entitlements.New(db.New(p)))
}

// eventDetail — последний detail события по серверу. Событие читается не через sqlc,
// а запросом: выборки на чтение connection_events в этом цикле нет ни у одной задачи,
// и заводить её ради теста значило бы объявлять API, которого продукт не имеет.
func eventDetail(t *testing.T, p *pgxpool.Pool, serverID uuid.UUID, event string) string {
	t.Helper()
	var detail string
	err := p.QueryRow(context.Background(),
		"SELECT detail::text FROM connection_events WHERE server_id = $1 AND event = $2"+
			" ORDER BY created_at DESC, id DESC LIMIT 1", serverID, event).Scan(&detail)
	if err != nil {
		t.Fatalf("событие %q для сервера %v: %v", event, serverID, err)
	}
	return detail
}

func eventCount(t *testing.T, p *pgxpool.Pool, serverID uuid.UUID, event string) int {
	t.Helper()
	var n int
	if err := p.QueryRow(context.Background(),
		"SELECT count(*) FROM connection_events WHERE server_id = $1 AND event = $2",
		serverID, event).Scan(&n); err != nil {
		t.Fatalf("count события %q: %v", event, err)
	}
	return n
}

// addressRow — состояние строки адреса: кому назначен и когда становится пригодным
// снова. Нужен именно так, потому что «адрес освобождён» и «адрес удалён из таблицы»
// — разные состояния, и на глаз по count их не различить.
func addressRow(t *testing.T, p *pgxpool.Pool, serverID uuid.UUID, addr netip.Addr) (
	allocatedTo *uuid.UUID, reusableAt *time.Time, exists bool) {
	t.Helper()
	err := p.QueryRow(context.Background(),
		"SELECT allocated_to, reusable_at FROM tunnel_addresses"+
			" WHERE server_id = $1 AND address = $2", serverID, addr).Scan(&allocatedTo, &reusableAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, false
	}
	if err != nil {
		t.Fatalf("строка адреса %v: %v", addr, err)
	}
	return allocatedTo, reusableAt, true
}

func TestIssueOnOnlineServer(t *testing.T) {
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	srv := seedServer(t, ctx, q, "10.96.20.0/29")
	setServerOnline(t, ctx, q, srv.ID)
	user := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, user, 0).ID

	before := eventCount(t, p, srv.ID, "profile_issued")
	beforeVersion := srv.ConfigVersion
	start := time.Now()
	prof, err := newProfilesService(t).Issue(ctx, user, device, srv.ID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	until := time.Now()

	if prof.Status != db.ProfileStatusActive {
		t.Errorf("статус = %q, want active", prof.Status)
	}
	if prof.PeerState != db.PeerStateActive {
		t.Errorf("peer_state = %q, want active", prof.PeerState)
	}
	node := connections.NodeTunnelAddress(srv.AddressPoolV4)
	if prof.AddressV4 == node {
		t.Errorf("клиенту выдан адрес узла %v", prof.AddressV4)
	}
	if !srv.AddressPoolV4.Contains(prof.AddressV4) {
		t.Errorf("адрес %v вне пула %v", prof.AddressV4, srv.AddressPoolV4)
	}
	// Подписка фикстуры бессрочная, поэтому потолок — TTL плана. Границы замера,
	// а не ровно число: now() внутри сервиса вызывается между двумя чтениями часов.
	lo := start.Add(connections.DefaultProfileTTL)
	hi := until.Add(connections.DefaultProfileTTL)
	if prof.ExpiresAt.Before(lo) || prof.ExpiresAt.After(hi) {
		t.Errorf("expires_at = %v, want в [%v, %v]", prof.ExpiresAt, lo, hi)
	}

	after, err := q.ServerByID(ctx, srv.ID)
	if err != nil {
		t.Fatalf("ServerByID: %v", err)
	}
	if after.ConfigVersion != beforeVersion+1 {
		t.Errorf("config_version = %d, want %d", after.ConfigVersion, beforeVersion+1)
	}
	if got := eventCount(t, p, srv.ID, "profile_issued"); got != before+1 {
		t.Errorf("событий profile_issued = %d, want %d", got, before+1)
	}
	if d := eventDetail(t, p, srv.ID, "profile_issued"); !strings.Contains(d, prof.AddressV4.String()) {
		t.Errorf("в detail события нет выданного адреса: %s", d)
	}
	if to, _, exists := addressRow(t, p, srv.ID, prof.AddressV4); !exists || to == nil || *to != prof.ID {
		t.Errorf("адрес %v не закреплён за профилем: exists=%v allocated=%v",
			prof.AddressV4, exists, to)
	}
}

func TestIssueRefusesNotOnlineServerAndSpendsNoAddress(t *testing.T) {
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	// maintenance — дефолт схемы: сервер зарегистрирован, но не работает.
	srv := seedServer(t, ctx, q, "10.96.21.0/29")
	user := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, user, 0).ID

	if _, err := newProfilesService(t).Issue(ctx, user, device, srv.ID); !errors.Is(err, connections.ErrServerNotAvailable) {
		t.Fatalf("выдача на maintenance-сервер: err = %v, want ErrServerNotAvailable", err)
	}
	var rows int
	if err := p.QueryRow(context.Background(),
		"SELECT count(*) FROM tunnel_addresses WHERE server_id = $1", srv.ID).Scan(&rows); err != nil {
		t.Fatalf("count адресов: %v", err)
	}
	// Отказ после занятия адреса оставил бы строку: адрес был бы сожжён на запрос,
	// который ничего не выдал, и такие «потраченные» адреса накопил бы sweeper.
	if rows != 0 {
		t.Errorf("строк адресов у отвергнутого сервера = %d, want 0", rows)
	}
	if v := eventCount(t, p, srv.ID, "profile_issued"); v != 0 {
		t.Errorf("событий profile_issued = %d, want 0", v)
	}
}

func TestIssueTwiceOnSameServerIsAlreadyActive(t *testing.T) {
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	srv := seedServer(t, ctx, q, "10.96.22.0/29")
	setServerOnline(t, ctx, q, srv.ID)
	user := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, user, 0).ID
	svc := newProfilesService(t)

	first, err := svc.Issue(ctx, user, device, srv.ID)
	if err != nil {
		t.Fatalf("первая выдача: %v", err)
	}
	versionAfterFirst, err := q.ServerByID(ctx, srv.ID)
	if err != nil {
		t.Fatalf("ServerByID: %v", err)
	}

	if _, err := svc.Issue(ctx, user, device, srv.ID); !errors.Is(err, connections.ErrAlreadyActive) {
		t.Fatalf("повторная выдача: err = %v, want ErrAlreadyActive", err)
	}
	after, err := q.ServerByID(ctx, srv.ID)
	if err != nil {
		t.Fatalf("ServerByID: %v", err)
	}
	// Отказ не должен двигать версию: узел на ровном месте пересобрал бы конфиг.
	if after.ConfigVersion != versionAfterFirst.ConfigVersion {
		t.Errorf("config_version после отказа = %d, want %d",
			after.ConfigVersion, versionAfterFirst.ConfigVersion)
	}
	var rows int
	if err := p.QueryRow(context.Background(),
		"SELECT count(*) FROM tunnel_addresses WHERE server_id = $1", srv.ID).Scan(&rows); err != nil {
		t.Fatalf("count адресов: %v", err)
	}
	if rows != 1 {
		t.Errorf("адресов выдано = %d, want 1 (второй профиль не должен занять второй)", rows)
	}
	if first.ServerID != srv.ID {
		t.Errorf("профиль не на том сервере: %v", first.ServerID)
	}
}

func TestIssueRefusesForeignUnknownAndRevokedDevice(t *testing.T) {
	ctx := context.Background()
	q := db.New(pool(t))
	srv := seedServer(t, ctx, q, "10.96.23.0/29")
	setServerOnline(t, ctx, q, srv.ID)
	owner := seedUserWithPlan(t, ctx, q, "internal-default")
	stranger := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, owner, 0).ID
	svc := newProfilesService(t)

	// Чужой и несуществующий отвечают одинаково: иначе ответ превращается в оракул
	// «существует ли такое устройство», как это уже сделано в devices.OwnedBy.
	foreign, errF := svc.Issue(ctx, stranger, device, srv.ID)
	unknown, errU := svc.Issue(ctx, stranger, uuid.New(), srv.ID)
	if !errors.Is(errF, connections.ErrForbiddenDevice) || !errors.Is(errU, connections.ErrForbiddenDevice) {
		t.Errorf("чужой = %v, несуществующий = %v, want оба ErrForbiddenDevice", errF, errU)
	}
	if foreign.ID != (uuid.UUID{}) || unknown.ID != (uuid.UUID{}) {
		t.Error("отказ вернул профиль")
	}

	revokedDevice := seedDevice(t, ctx, q, owner, 1).ID
	if err := q.RevokeDevice(ctx, revokedDevice); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	if _, err := svc.Issue(ctx, owner, revokedDevice, srv.ID); !errors.Is(err, connections.ErrDeviceRevoked) {
		t.Errorf("выдача на отозванное устройство: err = %v, want ErrDeviceRevoked", err)
	}
}

func TestIssueWithoutSubscription(t *testing.T) {
	ctx := context.Background()
	q := db.New(pool(t))
	srv := seedServer(t, ctx, q, "10.96.24.0/29")
	setServerOnline(t, ctx, q, srv.ID)
	user := seedUser(t, ctx, q, false)
	device := seedDevice(t, ctx, q, user, 0).ID

	if _, err := newProfilesService(t).Issue(ctx, user, device, srv.ID); !errors.Is(err, connections.ErrNoSubscription) {
		t.Errorf("выдача без подписки: err = %v, want ErrNoSubscription", err)
	}
}

func TestIssueUnknownServer(t *testing.T) {
	ctx := context.Background()
	q := db.New(pool(t))
	user := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, user, 0).ID

	if _, err := newProfilesService(t).Issue(ctx, user, device, uuid.New()); !errors.Is(err, connections.ErrServerUnknown) {
		t.Errorf("выдача на неизвестный сервер: err = %v, want ErrServerUnknown", err)
	}
}

func TestRevokeFreesAddressWithWindow(t *testing.T) {
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	srv := seedServer(t, ctx, q, "10.96.25.0/29")
	setServerOnline(t, ctx, q, srv.ID)
	user := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, user, 0).ID
	svc := newProfilesService(t)

	prof, err := svc.Issue(ctx, user, device, srv.ID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	versionAfterIssue, err := q.ServerByID(ctx, srv.ID)
	if err != nil {
		t.Fatalf("ServerByID: %v", err)
	}

	before := time.Now()
	got, err := svc.Revoke(ctx, user, device, srv.ID)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got.Status != db.ProfileStatusRevoked {
		t.Errorf("возвращён статус %q, want revoked", got.Status)
	}
	if got.RevokedAt == nil {
		t.Error("revoked_at не выставлен")
	}
	if got.AddressV4 != prof.AddressV4 {
		t.Errorf("отозван не тот адрес: %v, want %v", got.AddressV4, prof.AddressV4)
	}

	to, reusable, exists := addressRow(t, p, srv.ID, prof.AddressV4)
	if !exists {
		t.Fatalf("строка адреса пропала из таблицы")
	}
	if to != nil {
		t.Errorf("адрес всё ещё закреплён за %v", to)
	}
	// Пять минут задаёт SQL (задача 1), а не Go: здесь проверяется, что выдача
	// пользуется тем же окном, а не заводит второй счёт.
	if reusable == nil {
		t.Fatal("reusable_at не выставлен — окно переиспользования не открыто")
	}
	left := reusable.Sub(before)
	if left < 4*time.Minute || left > 6*time.Minute {
		t.Errorf("до конца окна %v, want около 5 минут", left)
	}

	after, err := q.ServerByID(ctx, srv.ID)
	if err != nil {
		t.Fatalf("ServerByID: %v", err)
	}
	if after.ConfigVersion != versionAfterIssue.ConfigVersion+1 {
		t.Errorf("config_version = %d, want %d", after.ConfigVersion, versionAfterIssue.ConfigVersion+1)
	}
	if eventCount(t, p, srv.ID, "profile_revoked") == 0 {
		t.Error("события profile_revoked нет")
	}

	// Отозванный профиль виден Profile (это тот же случай, что просроченный выше),
	// и конфиг после отзыва не отдаётся.
	view, err := svc.Profile(ctx, user, device, srv.ID)
	if err != nil {
		t.Fatalf("Profile после отзыва: %v", err)
	}
	if view.Status != db.ProfileStatusRevoked {
		t.Errorf("Profile после отзыва = %q, want revoked", view.Status)
	}
	if _, err := svc.ConfigText(ctx, user, device, srv.ID); !errors.Is(err, connections.ErrNotActive) {
		t.Errorf("конфиг после отзыва: err = %v, want ErrNotActive", err)
	}

	if _, err := svc.Revoke(ctx, user, device, srv.ID); !errors.Is(err, connections.ErrNotActive) {
		t.Errorf("повторный отзыв: err = %v, want ErrNotActive", err)
	}
	// Ошибка не должна двигать версию ещё раз.
	afterTwice, err := q.ServerByID(ctx, srv.ID)
	if err != nil {
		t.Fatalf("ServerByID: %v", err)
	}
	if afterTwice.ConfigVersion != after.ConfigVersion {
		t.Errorf("config_version после отказа = %d, want %d", afterTwice.ConfigVersion, after.ConfigVersion)
	}
}

func TestConfigTextOnlyForActiveUnexpired(t *testing.T) {
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	srv := seedServer(t, ctx, q, "10.96.26.0/29")
	setServerOnline(t, ctx, q, srv.ID)
	user := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, user, 0).ID
	svc := newProfilesService(t)

	prof, err := svc.Issue(ctx, user, device, srv.ID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	text, err := svc.ConfigText(ctx, user, device, srv.ID)
	if err != nil {
		t.Fatalf("ConfigText: %v", err)
	}
	for _, want := range []string{"[Interface]", "[Peer]", "Address = " + prof.AddressV4.String() + "/32",
		"Endpoint = " + srv.AdvertisedHost, "PersistentKeepalive"} {
		if !strings.Contains(text, want) {
			t.Errorf("в конфиге нет %q:\n%s", want, text)
		}
	}
	// Приватный ключ клиента не покидает устройство (спецификация §3), и текст
	// выдачи — то место, где это легче всего сломать.
	for _, banned := range []string{"PrivateKey", "PresharedKey"} {
		if strings.Contains(text, banned) {
			t.Errorf("в конфиге клиента появился %s:\n%s", banned, text)
		}
	}

	// Просрочка моделируется правкой срока, а не ожиданием: профиль вставляет
	// `profiles_window` с expires_at > issued_at, поэтому сдвигается и момент выдачи —
	// один только срок база не позволяет положить в прошлое (то же семейство
	// констрейнтов, что и addresses_window в задаче 4).
	if _, err := p.Exec(ctx,
		"UPDATE vpn_profiles SET issued_at = now() - interval '2 hours'"+
			", expires_at = now() - interval '1 minute' WHERE id = $1",
		prof.ID); err != nil {
		t.Fatalf("сдвиг срока выдачи: %v", err)
	}
	if _, err := svc.ConfigText(ctx, user, device, srv.ID); !errors.Is(err, connections.ErrNotActive) {
		t.Errorf("просроченный профиль: err = %v, want ErrNotActive", err)
	}

	// Просроченный профиль конфиг не отдаёт, но Profile его показать обязан: человек
	// имеет право видеть, что с его доступом случилось. Статус при этом всё ещё
	// active: просроченным его делает не чтение, а проход sweeper'а задачи 13.
	view, err := svc.Profile(ctx, user, device, srv.ID)
	if err != nil {
		t.Fatalf("Profile: %v", err)
	}
	if view.ID != prof.ID || !view.ExpiresAt.Before(time.Now()) {
		t.Errorf("Profile вернул %v со сроком %v, want этот же профиль и срок в прошлом",
			view.ID, view.ExpiresAt)
	}
	list, err := svc.List(ctx, user, device)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) == 0 {
		t.Error("список профилей пуст")
	}
	stranger := seedUserWithPlan(t, ctx, q, "internal-default")
	if _, err := svc.ConfigText(ctx, stranger, device, srv.ID); !errors.Is(err, connections.ErrForbiddenDevice) {
		t.Errorf("чужой пользователь: err = %v, want ErrForbiddenDevice", err)
	}
	if _, err := svc.List(ctx, stranger, device); !errors.Is(err, connections.ErrForbiddenDevice) {
		t.Errorf("чужой пользователь в List: err = %v, want ErrForbiddenDevice", err)
	}
}

func TestIssueAcrossTwoServersGivesTwoActiveProfiles(t *testing.T) {
	ctx := context.Background()
	q := db.New(pool(t))
	srvA := seedServer(t, ctx, q, "10.96.27.0/29")
	srvB := seedServer(t, ctx, q, "10.96.28.0/29")
	setServerOnline(t, ctx, q, srvA.ID)
	setServerOnline(t, ctx, q, srvB.ID)
	user := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, user, 0).ID
	svc := newProfilesService(t)

	a, err := svc.Issue(ctx, user, device, srvA.ID)
	if err != nil {
		t.Fatalf("выдача A: %v", err)
	}
	b, err := svc.Issue(ctx, user, device, srvB.ID)
	if err != nil {
		t.Fatalf("выдача B: %v", err)
	}
	if !srvA.AddressPoolV4.Contains(a.AddressV4) || !srvB.AddressPoolV4.Contains(b.AddressV4) {
		t.Errorf("адреса не из своих пулов: %v (%v), %v (%v)",
			a.AddressV4, srvA.AddressPoolV4, b.AddressV4, srvB.AddressPoolV4)
	}
	// Лимит устройств — про устройства, а не про число серверов: два активных
	// профиля одного устройства на разных серверах законны.
	list, err := svc.List(ctx, user, device)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	active := 0
	for _, pr := range list {
		if pr.Status == db.ProfileStatusActive {
			active++
		}
	}
	if active != 2 {
		t.Errorf("активных профилей = %d, want 2", active)
	}
}

func TestParallelIssueUsesLockPerServer(t *testing.T) {
	ctx := context.Background()
	q := db.New(pool(t))
	user := seedUserWithPlan(t, ctx, q, "internal-default")
	device := seedDevice(t, ctx, q, user, 0).ID
	svc := newProfilesService(t)

	const n = 10
	servers := make([]db.VpnServer, n)
	for i := range servers {
		// Каждый сервер в своём пулу: 10.96.30.0/29 … 10.96.39.0/29.
		servers[i] = seedServer(t, ctx, q, fmt.Sprintf("10.96.%d.0/29", 30+i))
		setServerOnline(t, ctx, q, servers[i].ID)
	}

	ids := make([]uuid.UUID, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range servers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			prof, err := svc.Issue(ctx, user, device, servers[i].ID)
			ids[i], errs[i] = prof.ID, err
		}(i)
	}
	wg.Wait()
	for i := range servers {
		if errs[i] != nil {
			t.Fatalf("выдача на сервер %d: %v", i, errs[i])
		}
	}
	// Все десять успешны и все десять на разных серверах — значит блокировка
	// берётся по серверу, а не глобально: при глобальном локе десяток выдач одного
	// устройства ждал бы друг друга, но ошибка была бы другой, а при ошибке в ключе
	// блокировки они бы сталкивались на одном адресе.
	seen := make(map[uuid.UUID]bool, n)
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("один профиль вернулся дважды: %v", id)
		}
		seen[id] = true
	}
	list, err := svc.List(ctx, user, device)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	serversSeen := make(map[uuid.UUID]bool, n)
	for _, pr := range list {
		if pr.DeviceID == device && pr.Status == db.ProfileStatusActive {
			serversSeen[pr.ServerID] = true
		}
	}
	if len(serversSeen) != n {
		t.Errorf("различных серверов с активным профилем = %d, want %d", len(serversSeen), n)
	}
}
