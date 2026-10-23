package connections

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/novavpn/novavpn/internal/db"
)

// Границы маски пула. Нижняя (30) взята не из удобства: при /31 и /32 в пуле не
// остаётся ни одного клиентского адреса (base — сеть, base+1 — узел, и до
// broadcast-адреса очередь не доходит), поэтому выдавать такой пул бессмысленно,
// а не «опасно». Верхняя (24) ограничивает размер выборки: пул крупнее /24 —
// почти всегда ошибка конфигурации, и молча обойти 16 млн адресов значит
// спрятать её за первой выдачей.
const (
	minPoolBits = 24
	maxPoolBits = 30
)

var (
	// ErrPoolExhausted — в пуле не осталось свободных адресов до конца окна
	// переиспользования. Для клиента это не «вы плохи», а «сервер заполнен»:
	// задача 6 отображает его в отдельный код ответа.
	ErrPoolExhausted = errors.New("connections: пул адресов исчерпан")
	// ErrAddressRace — адрес успели занять между Go-выборкой и занятием в базе.
	// Означает, что кто-то обошёл advisory lock; вызывающий вправе повторить
	// выдачу, но не обязан делать это вечно.
	ErrAddressRace = errors.New("connections: адрес занят параллельной выдачей")
)

func addrToU32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func u32ToAddr(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// clientPool нормализует пул и проверяет, что из него можно выдавать адреса.
// Хостовые биты обнуляются, а не отвергаются: колонка cidr в PostgreSQL делает то
// же на вводе, так что отказ значению, которое база сама привела бы к сети,
// расходился бы с тем, что уже лежит в таблице.
func clientPool(pool netip.Prefix) (netip.Prefix, error) {
	if !pool.IsValid() || !is4(pool.Addr()) {
		return netip.Prefix{}, fmt.Errorf("connections: пул %q не IPv4", pool)
	}
	bits := pool.Bits()
	if bits < minPoolBits || bits > maxPoolBits {
		return netip.Prefix{}, fmt.Errorf(
			"connections: маска пула /%d вне диапазона /%d../%d", bits, minPoolBits, maxPoolBits)
	}
	return pool.Masked(), nil
}

// PickAddress возвращает минимальный по числовому порядку свободный адрес пула.
//
// Кандидаты — base+2 .. last-1: base это сеть, base+1 адрес узла (он же recursor
// в туннеле, см. NodeTunnelAddress), last broadcast. Отсюда следуют два факта,
// которые проверяет тест: в /30 ровно один клиентский адрес (base+2), и адрес
// узла не может быть выдан никогда — он вне диапазона, а не «отфильтрован
// забытым условием». Поэтому busy не нужно заранее знать про адрес узла:
// добавлять его туда было бы кодом, который ни один тест не отличает от мёртвого.
//
// Обход числовой, а не netip.Prefix.Range: детерминизм нужен, чтобы две выдачи
// подряд не зависели от обхода карты, и чтобы исчерпание наступало по одному и
// тому же правилу на любой реализации.
func PickAddress(pool netip.Prefix, busy map[netip.Addr]bool) (netip.Addr, error) {
	p, err := clientPool(pool)
	if err != nil {
		return netip.Addr{}, err
	}
	base := addrToU32(p.Addr())
	// 32-bits <= 8 по проверке маски, поэтому сдвига в uint32 не произойдёт.
	last := base + uint32(1)<<(32-uint(p.Bits())) - 1
	first, upto := base+2, last-1
	for v := first; v <= upto; v++ {
		if busy[u32ToAddr(v)] {
			continue
		}
		return u32ToAddr(v), nil
	}
	return netip.Addr{}, ErrPoolExhausted
}

// Allocate выбирает адрес для выдачи. Вызывается строго внутри транзакции
// вызывающего: q обязан быть построен на том же pgx.Tx, иначе advisory lock
// продержится не до конца выдачи, а до возврата из этой функции, и вторая горутина
// увидит свободным адрес, который уже отдан.
//
// Порядок именно такой, потому что данные читаются после блокировки: сначала
// сериализация на сервер (LockServerRow), затем актуальный список занятых, затем
// выборка. Выборка до блокировки читала бы список, который параллельная выдача уже
// изменила.
//
// Занятие адреса — отдельный шаг (Claim), а не часть этой функции, и причина не в
// читаемости: allocated_to ссылается на vpn_profiles(id), а PostgreSQL проверяет
// этот Foreign Key сразу на вставке. Строка профиля обязана существовать раньше,
// чем адрес занят, а профиль вставляется только вместе со своим адресом — то есть
// между выборкой и занятием стоит INSERT профиля. Смешать их в одну функцию, не
// соврав про порядок, нельзя.
func Allocate(ctx context.Context, q *db.Queries, srv db.VpnServer) (netip.Addr, error) {
	if err := q.LockServerRow(ctx, srv.ID.String()); err != nil {
		return netip.Addr{}, fmt.Errorf("connections: блокировка сервера %v: %w", srv.ID, err)
	}
	used, err := q.BusyAddresses(ctx, srv.ID)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("connections: занятые адреса %v: %w", srv.ID, err)
	}
	busy := make(map[netip.Addr]bool, len(used))
	for _, a := range used {
		busy[a] = true
	}
	return PickAddress(srv.AddressPoolV4, busy)
}

// Claim занимает выбранный адрес за профилем. Это вторая линия защиты, и она не
// лишняя поверх advisory lock: lock сериализует выдачу этого сервера только для тех,
// кто его берёт, а прямой вызов или будущая админ-операция могут его обойти.
// ClaimAddress с ON CONFLICT DO UPDATE ... WHERE не вернёт строку, если адрес успели
// занять или его окно переиспользования (§7.2) ещё открыто, и тогда выдача
// отказывается, а не перетирает чужое назначение.
//
// Повтор внутри этой функции не делается, и это не забытая часть плана: между
// выборкой и занятием уже вставлена строка профиля, поэтому «повторить только
// занятие» невозможно — прежняя вставка мешала бы, а её откат означал бы откат всей
// транзакции. Повтор целиком на вызывающем (задача 5) и обязан быть конечным:
// бесконечный повтор превратил бы обход блокировки в вечно висящий запрос.
func Claim(ctx context.Context, q *db.Queries, srv db.VpnServer, addr netip.Addr, profileID uuid.UUID) error {
	_, err := q.ClaimAddress(ctx, db.ClaimAddressParams{
		ServerID:    srv.ID,
		Address:     addr,
		AllocatedTo: &profileID,
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, pgx.ErrNoRows):
		return ErrAddressRace
	default:
		return fmt.Errorf("connections: занятие адреса %v: %w", addr, err)
	}
}
