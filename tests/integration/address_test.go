//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/novavpn/novavpn/internal/connections"
	"github.com/novavpn/novavpn/internal/db"
)

// poolSlots — сколько адресов пула отдаётся клиентам: размер минус сеть, адрес узла
// и broadcast. Число выводится из маски, а не переписывается константой рядом с
// тестом: «/28 = 13» устарело бы молча на первой же правке границы, и тест ждал бы
// не того количества.
func poolSlots(p netip.Prefix) int {
	return 1<<(32-p.Bits()) - 3
}

// issueAddress повторяет путь выдачи ровно в том порядке, которого требует Foreign
// Key allocated_to → vpn_profiles(id): выборка под блокировкой, затем строка
// профиля, затем занятие адреса. Разворотить последние два шага нельзя — это
// проверяет не аккуратность, а схему (см. комментарий connections.Claim).
//
// Пул и профиль возвращаются, а не «падают» на t.Fatalf: функция вызывается из
// горутин, где Fail запрещён, и решение об ошибке принимает тест в основном
// потоке.
func issueAddress(p *pgxpool.Pool, srv db.VpnServer, deviceID uuid.UUID) (netip.Addr, uuid.UUID, error) {
	ctx := context.Background()
	var addr netip.Addr
	var profileID uuid.UUID
	err := db.RunInTx(ctx, p, func(q *db.Queries) error {
		a, err := connections.Allocate(ctx, q, srv)
		if err != nil {
			return err
		}
		prof, err := q.InsertProfile(ctx, db.InsertProfileParams{
			ID: uuid.New(), DeviceID: deviceID, ServerID: srv.ID,
			AddressV4: a, ExpiresAt: time.Now().Add(time.Hour),
		})
		if err != nil {
			return fmt.Errorf("InsertProfile: %w", err)
		}
		if err := connections.Claim(ctx, q, srv, a, prof.ID); err != nil {
			return err
		}
		addr, profileID = a, prof.ID
		return nil
	})
	return addr, profileID, err
}

// allocationCount — сколько строк addresses у сервера; отдельно от занятых, чтобы
// «выдано» и «не оставлено мусора» были разными утверждениями.
func allocationCount(t *testing.T, p *pgxpool.Pool, srvID uuid.UUID) int {
	t.Helper()
	var n int
	if err := p.QueryRow(context.Background(),
		"SELECT count(*) FROM tunnel_addresses WHERE server_id = $1", srvID).Scan(&n); err != nil {
		t.Fatalf("count tunnel_addresses: %v", err)
	}
	return n
}

// distinctCount — сколько различных адресов у сервера. Это и есть проверка «нет
// двойной выдачи»: дубликат в tunnel_addresses первичным ключом не ловится (пара
// «сервер, адрес» как раз уникальна), его ловит только сравнение множеств.
func distinctCount(t *testing.T, p *pgxpool.Pool, srvID uuid.UUID) int {
	t.Helper()
	var n int
	if err := p.QueryRow(context.Background(),
		"SELECT count(DISTINCT address) FROM tunnel_addresses WHERE server_id = $1", srvID).Scan(&n); err != nil {
		t.Fatalf("count distinct: %v", err)
	}
	return n
}

func TestAllocateConcurrentIssuanceGivesDistinctAddresses(t *testing.T) {
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	// 10 горутин на /28 (13 клиентских адресов): пул заведомо не на пределе, и
	// успех всех десяти означает «блокировка не подпустила вторую выдачу к тому же
	// адресу», а не «повезло разойтись».
	const n = 10
	srv := seedServer(t, ctx, q, "10.97.11.0/28")
	user := seedUser(t, ctx, q, false)
	devices := make([]uuid.UUID, n)
	for i := range devices {
		devices[i] = seedDevice(t, ctx, q, user, i).ID
	}

	addrs := make([]netip.Addr, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range devices {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			addrs[i], _, errs[i] = issueAddress(p, srv, devices[i])
		}(i)
	}
	wg.Wait()

	seen := make(map[netip.Addr]bool, n)
	for i := range devices {
		if errs[i] != nil {
			t.Fatalf("выдача %d: %v", i, errs[i])
		}
		if seen[addrs[i]] {
			t.Fatalf("адрес %v выдан дважды (выдача %d)", addrs[i], i)
		}
		seen[addrs[i]] = true
		if addrs[i] == connections.NodeTunnelAddress(srv.AddressPoolV4) {
			t.Fatalf("клиенту выдан адрес узла %v", addrs[i])
		}
	}
	if got := distinctCount(t, p, srv.ID); got != n {
		t.Errorf("в базе различных адресов = %d, want %d", got, n)
	}
	if got := allocationCount(t, p, srv.ID); got != n {
		t.Errorf("строк в tunnel_addresses = %d, want %d", got, n)
	}
}

func TestAllocateStopsAtPoolCapacityAndNeverIssuesNodeAddress(t *testing.T) {
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	poolPrefix := netip.MustParsePrefix("10.97.12.0/28")
	srv := seedServer(t, ctx, q, poolPrefix.String())
	capacity := poolSlots(poolPrefix)

	// Профилей на одну выдачу больше, чем адресов: лишние обязаны уйти отказом по
	// исчерпанию пула, а не встать в очередь и занять чужое место после отзыва.
	user := seedUser(t, ctx, q, false)
	total := capacity + 2
	devices := make([]uuid.UUID, total)
	for i := range devices {
		devices[i] = seedDevice(t, ctx, q, user, i).ID
	}

	addrs := make([]netip.Addr, total)
	errs := make([]error, total)
	var wg sync.WaitGroup
	for i := range devices {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			addrs[i], _, errs[i] = issueAddress(p, srv, devices[i])
		}(i)
	}
	wg.Wait()

	var ok, exhausted, races int
	for i := range devices {
		switch {
		case errs[i] == nil:
			ok++
		case errors.Is(errs[i], connections.ErrPoolExhausted):
			exhausted++
		case errors.Is(errs[i], connections.ErrAddressRace):
			races++
		default:
			t.Fatalf("выдача %d: неожиданная ошибка %v", i, errs[i])
		}
	}
	// Адрес узла (base+1) не должен появиться ни в одном успешном ответе и ни в
	// одной строке базы: он вне диапазона кандидатов, и это единственный способ
	// поймать ошибку, при которой «свободный» адрес узла кому-то отдали.
	node := connections.NodeTunnelAddress(poolPrefix)
	for i := range devices {
		if errs[i] == nil && addrs[i] == node {
			t.Errorf("выдача %d получила адрес узла %v", i, addrs[i])
		}
	}
	if ok != capacity {
		t.Errorf("успешных выдач = %d, want %d (ёмкость пула)", ok, capacity)
	}
	if exhausted+races != total-ok {
		t.Errorf("отказов %d+%d, want %d", exhausted, races, total-ok)
	}
	if exhausted == 0 && races == 0 {
		t.Error("переполнение пула не отвергнуто ни одной выдачей")
	}
	if got := distinctCount(t, p, srv.ID); got != ok {
		t.Errorf("различных адресов в базе = %d, want %d", got, ok)
	}
	var nodeRows int
	if err := p.QueryRow(context.Background(),
		"SELECT count(*) FROM tunnel_addresses WHERE server_id = $1 AND address = $2",
		srv.ID, node).Scan(&nodeRows); err != nil {
		t.Fatalf("count адрес узла: %v", err)
	}
	if nodeRows != 0 {
		t.Errorf("адрес узла %v занял %d строк в tunnel_addresses", node, nodeRows)
	}
}

func TestReleasedAddressIsNotTakenUntilWindowCloses(t *testing.T) {
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	// /29: пять клиентских адресов (.2 … .6), из них .2 занимает первая выдача.
	srv := seedServer(t, ctx, q, "10.97.13.0/29")
	user := seedUser(t, ctx, q, false)

	first, firstProfile, err := issueAddress(p, srv, seedDevice(t, ctx, q, user, 0).ID)
	if err != nil {
		t.Fatalf("первая выдача: %v", err)
	}
	if want := netip.MustParseAddr("10.97.13.2"); first != want {
		t.Fatalf("первая выдача = %v, want %v", first, want)
	}
	if err := q.ReleaseAddressByProfile(ctx, &firstProfile); err != nil {
		t.Fatalf("ReleaseAddressByProfile: %v", err)
	}

	// Освобождённый адрес остаётся занятым до конца окна (§7.2), поэтому вторая
	// выдача обязана взять следующий, а не тот же.
	second, _, err := issueAddress(p, srv, seedDevice(t, ctx, q, user, 1).ID)
	if err != nil {
		t.Fatalf("вторая выдача: %v", err)
	}
	if want := netip.MustParseAddr("10.97.13.3"); second != want {
		t.Errorf("вторая выдача = %v, want %v (окно переиспользования открыто)", second, want)
	}

	// Окно закрыто по часам сервера, поэтому и сдвигается в базе. Двигаются оба
	// поля сразу: констрейнт addresses_window требует reusable_at >= released_at, и
	// правка одного из них была бы отказом базы, а не тестом.
	if _, err := p.Exec(ctx,
		"UPDATE tunnel_addresses SET released_at = now() - interval '6 minutes'"+
			", reusable_at = now() - interval '1 minute'"+
			" WHERE server_id = $1 AND address = $2", srv.ID, first); err != nil {
		t.Fatalf("сдвиг окна переиспользования: %v", err)
	}
	third, _, err := issueAddress(p, srv, seedDevice(t, ctx, q, user, 2).ID)
	if err != nil {
		t.Fatalf("третья выдача: %v", err)
	}
	if third != first {
		t.Errorf("после закрытия окна выдан %v, want %v (адрес вернулся в пул)", third, first)
	}
}

func TestSamePoolOnTwoServersIsAllocatedIndependently(t *testing.T) {
	ctx := context.Background()
	p := pool(t)
	q := db.New(p)
	// Два сервера с одним и тем же пулом: первичный ключ — пара (server_id,
	// address), поэтому совпадение адресов это норма, а не коллизия (спецификация §6).
	poolStr := "10.97.14.0/29"
	a := seedServer(t, ctx, q, poolStr)
	b := seedServer(t, ctx, q, poolStr)
	user := seedUser(t, ctx, q, false)

	addrA, _, err := issueAddress(p, a, seedDevice(t, ctx, q, user, 0).ID)
	if err != nil {
		t.Fatalf("выдача на сервере A: %v", err)
	}
	addrB, _, err := issueAddress(p, b, seedDevice(t, ctx, q, user, 1).ID)
	if err != nil {
		t.Fatalf("выдача на сервере B: %v", err)
	}
	if addrA != addrB {
		t.Errorf("адреса разошлись: A = %v, B = %v", addrA, addrB)
	}
	if got := allocationCount(t, p, a.ID); got != 1 {
		t.Errorf("строк у A = %d, want 1", got)
	}
	if got := allocationCount(t, p, b.ID); got != 1 {
		t.Errorf("строк у B = %d, want 1", got)
	}
}
