package devices

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/novavpn/novavpn/internal/connections"
	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/entitlements"
)

var (
	ErrDeviceLimit     = errors.New("device limit reached")
	ErrDuplicateKey    = errors.New("device with this public key already exists")
	ErrForbiddenDevice = errors.New("device belongs to another user")
	ErrInvalidKey      = errors.New("public key is invalid")
	ErrInvalidPlatform = errors.New("platform is invalid")
	ErrInvalidName     = errors.New("name must be 1..64 characters")
	// ErrDeviceRevoked — устройство уже отозвано. HTTP-слой отвечает на него тем же
	// 404, что и на чужое: различие «отозвано» и «не твоё» ничего не меняет для
	// вызывающего, а по отдельному ответу его можно было бы различать.
	ErrDeviceRevoked = errors.New("device is revoked")
	// ErrNotLiveDevice — ротация отозванного устройства. Отдельный страж, а не
	// ErrDeviceRevoked из пути выдачи: HTTP-слой обязан ответить 409 с причиной,
	// потому что «повтори запрос» тут бесполезно — нужно новое устройство.
	ErrNotLiveDevice = errors.New("device is not live")
)

type RegisterInput struct {
	PublicKey string
	Platform  string
	Name      string
}

type Service struct {
	pool *pgxpool.Pool
	q    *db.Queries // читает без транзакции; пишущие пути берут tx внутри RunInTx
	ent  *entitlements.Service
}

func NewService(pool *pgxpool.Pool, ent *entitlements.Service) *Service {
	return &Service{pool: pool, q: db.New(pool), ent: ent}
}

// Register — единственное место, где жёсткая часть лимита устройств (спецификация §7.4):
// count и insert в одной транзакции под advisory lock пользователя. Без lock два
// параллельных запроса оба увидели бы «место есть».
func (s *Service) Register(ctx context.Context, userID uuid.UUID, in RegisterInput) (db.Device, error) {
	if _, err := ParsePublicKey(in.PublicKey); err != nil {
		return db.Device{}, ErrInvalidKey
	}
	if !ValidPlatform(in.Platform) {
		return db.Device{}, ErrInvalidPlatform
	}
	if l := len(in.Name); l < 1 || l > 64 {
		return db.Device{}, ErrInvalidName
	}

	ent, err := s.ent.ForUser(ctx, userID)
	if err != nil {
		return db.Device{}, err
	}

	var created db.Device
	err = db.RunInTx(ctx, s.pool, func(tx *db.Queries) error {
		if err := tx.LockUserForDeviceCount(ctx, userID.String()); err != nil {
			return fmt.Errorf("advisory lock: %w", err)
		}
		// Дубликат проверяется до лимита: повторный запрос с тем же ключом обязан
		// ответить ErrDuplicateKey, даже когда лимит уже исчерпан.
		if existing, err := tx.DeviceByUserAndKey(ctx, db.DeviceByUserAndKeyParams{
			UserID: userID, PublicKey: in.PublicKey,
		}); err == nil && existing.RevokedAt == nil {
			return ErrDuplicateKey
		} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("lookup by key: %w", err)
		}
		live, err := tx.CountLiveDevices(ctx, userID)
		if err != nil {
			return fmt.Errorf("count devices: %w", err)
		}
		if !ent.AllowsDevice(int(live)) {
			return ErrDeviceLimit
		}
		created, err = tx.InsertDevice(ctx, db.InsertDeviceParams{
			ID: uuid.New(), UserID: userID, PublicKey: in.PublicKey,
			Platform: db.DevicePlatform(in.Platform), Name: in.Name,
		})
		if isUniqueViolation(err) {
			// Гонка между двумя запросами на (user_id, public_key).
			return ErrDuplicateKey
		}
		return err
	})
	if err != nil {
		return db.Device{}, err
	}
	return created, nil
}

func (s *Service) List(ctx context.Context, userID uuid.UUID) ([]db.Device, error) {
	return s.q.LiveDevicesByUser(ctx, userID)
}

// OwnedBy — проверка права на объект, а не только факта аутентификации (спецификация §5.2).
// Чужое устройство отдаётся той же ошибкой, что и несуществующий, чтобы не строить
// оракул «есть ли у кого-то такой id».
func (s *Service) OwnedBy(ctx context.Context, deviceID, userID uuid.UUID) (db.Device, error) {
	d, err := s.q.DeviceByID(ctx, deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return db.Device{}, ErrForbiddenDevice
	}
	if err != nil {
		return db.Device{}, err
	}
	if d.UserID != userID {
		return db.Device{}, ErrForbiddenDevice
	}
	return d, nil
}

// mergeUnique объединяет два обхода цепочки в одно множество id. Порядок не важен:
// результат уходит в ANY(...) и в пакетные UPDATE, где значимо только «без дублей» —
// предок и потомок сходятся в самом запрашиваемом устройстве.
func mergeUnique(a, b []uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]bool, len(a)+len(b))
	out := make([]uuid.UUID, 0, len(a)+len(b))
	for _, group := range [][]uuid.UUID{a, b} {
		for _, id := range group {
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// DeleteDevice отзывает устройство вместе со всей цепочкой ротации и возвращает число
// отозванных профилей.
//
// Всё — одной транзакцией, включая проверку владельца: между проверкой и отзывом
// профилей пользователь мог бы получить ещё один профиль, и он остался бы активным при
// «удалённом» устройстве. Вне транзакции эта гонка не видна ни на одном тесте, потому
// что каждый шаг сам по себе правильный.
//
// Цепочка берётся целиком, в обе стороны: отзыв потомка обязан закрыть overlap предка
// (§7.3), а отзыв родителя обязан погасить потомка — для пользователя это то же
// устройство с новым ключом.
func (s *Service) DeleteDevice(ctx context.Context, userID, deviceID uuid.UUID) (int, error) {
	revokedProfiles := 0
	err := db.RunInTx(ctx, s.pool, func(q *db.Queries) error {
		d, err := q.DeviceByID(ctx, deviceID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrForbiddenDevice
		}
		if err != nil {
			return fmt.Errorf("device by id: %w", err)
		}
		if d.UserID != userID {
			return ErrForbiddenDevice
		}
		if d.RevokedAt != nil {
			return ErrDeviceRevoked
		}

		// Цепочка собирается из двух обходов: вверх по rotation_of и вниз по нему же.
		// Одним запросом это не выражено: PostgreSQL принимает CTE, объединяющий два
		// рекурсивных CTE, но sqlc 1.27.0 его разобрать не может («column reference
		// \"id\" is ambiguous»), а вариант с двумя рекурсивными ветвями в одном CTE
		// отклоняет сам сервер. Два запроса — то же самое множество, и именно оно нужно.
		ancestors, err := q.RotationAncestorIDs(ctx, deviceID)
		if err != nil {
			return fmt.Errorf("rotation ancestors of %v: %w", deviceID, err)
		}
		descendants, err := q.RotationDescendantIDs(ctx, deviceID)
		if err != nil {
			return fmt.Errorf("rotation descendants of %v: %w", deviceID, err)
		}
		chain := mergeUnique(ancestors, descendants)
		// Цепочка считается по ссылке rotation_of, а не по владельцу: если данные
		// когда-нибудь свяжут устройства разных пользователей (прямая правка, будущий
		// перенос), отзыв одного человека погасил бы чужие профили. Проверка на месте
		// дешевле, чем разбор последствий, и цепочка заведомо короткая.
		for _, id := range chain {
			node, err := q.DeviceByID(ctx, id)
			if err != nil {
				return fmt.Errorf("chain node %v: %w", id, err)
			}
			if node.UserID != userID {
				return ErrForbiddenDevice
			}
		}

		if err := q.RevokeDevices(ctx, chain); err != nil {
			return fmt.Errorf("revoke devices: %w", err)
		}
		rows, err := q.RevokeProfilesForDevices(ctx, chain)
		if err != nil {
			return fmt.Errorf("revoke profiles: %w", err)
		}
		if len(rows) > 0 {
			ids := make([]uuid.UUID, 0, len(rows))
			for _, row := range rows {
				ids = append(ids, row.ID)
			}
			// Освобождение адреса — одним пакетом, а не по профилю: окно
			// переиспользования (§7.2) открывает SQL, и повторять ему вызов по каждому
			// строке значило бы давать базе два шанса разойтись.
			if err := q.ReleaseAddressesByProfiles(ctx, ids); err != nil {
				return fmt.Errorf("release addresses: %w", err)
			}
		}

		// Версия поднимается один раз на сервер, а не на профиль: узел сравнивает
		// версию, и три профиля на одном сервере не значат три разных множества пиеров.
		seen := make(map[uuid.UUID]bool, len(rows))
		for _, row := range rows {
			if seen[row.ServerID] {
				continue
			}
			seen[row.ServerID] = true
			if _, err := q.BumpServerConfigVersion(ctx, row.ServerID); err != nil {
				return fmt.Errorf("bump config version of %v: %w", row.ServerID, err)
			}
		}
		// Событие на каждый отозванный профиль: «устройство удалено» без перечня
		// профилей не отвечает на вопрос, кому именно и когда закрыли доступ.
		detail, err := json.Marshal(map[string]any{"reason": "device_deleted"})
		if err != nil {
			return fmt.Errorf("marshal detail: %w", err)
		}
		for _, row := range rows {
			owner, deviceID, serverID := row.UserID, row.DeviceID, row.ServerID
			if err := q.InsertConnectionEvent(ctx, db.InsertConnectionEventParams{
				UserID: &owner, DeviceID: &deviceID, ServerID: &serverID,
				Event: db.EventTypeProfileRevoked, Detail: detail,
			}); err != nil {
				return fmt.Errorf("event profile_revoked: %w", err)
			}
		}
		revokedProfiles = len(rows)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return revokedProfiles, nil
}

// RotateKey меняет публичный ключ устройства: создаётся потомок с новым ключом,
// профили предка переходят в overlap, а адреса остаются за клиентом (§7.3).
//
// Направление импорта — devices → connections: окном владеет профиль, а не
// устройство, и запрет задачи 3 стоит на обратном направлении.
//
// Проверка лимита устройств в этом пути не делается, и это не дыра: предок отзывается в
// той же транзакции, поэтому живых устройств не становится больше. Без этой слабости ротация на исчерпанном лимите
// была бы невозможна, а «потомок как четвёртое
// устройство» сломал бы обещание ТЗ о совместимости.
func (s *Service) RotateKey(ctx context.Context, userID, parentID uuid.UUID, newPublicKey string) (db.Device, error) {
	if _, err := ParsePublicKey(newPublicKey); err != nil {
		return db.Device{}, ErrInvalidKey
	}

	var created db.Device
	err := db.RunInTx(ctx, s.pool, func(q *db.Queries) error {
		parent, err := q.DeviceByID(ctx, parentID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrForbiddenDevice
		}
		if err != nil {
			return fmt.Errorf("device by id: %w", err)
		}
		if parent.UserID != userID {
			return ErrForbiddenDevice
		}
		if parent.RevokedAt != nil {
			return ErrNotLiveDevice
		}
		// Дубликат проверяется до вставки и до всего остального: повтор с ключом
		// живого устройства обязан ответить duplicate_device, а не упереться в
		// уникальный индекс посреди транзакции (как в Register).
		if existing, err := q.DeviceByUserAndKey(ctx, db.DeviceByUserAndKeyParams{
			UserID: userID, PublicKey: newPublicKey,
		}); err == nil && existing.RevokedAt == nil {
			return ErrDuplicateKey
		} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("lookup by key: %w", err)
		}

		created, err = q.InsertDevice(ctx, db.InsertDeviceParams{
			ID: uuid.New(), UserID: userID, PublicKey: newPublicKey,
			Platform: parent.Platform, Name: parent.Name, RotationOf: &parent.ID,
		})
		if err != nil {
			if isUniqueViolation(err) {
				return ErrDuplicateKey
			}
			return fmt.Errorf("insert rotated device: %w", err)
		}

		overlap := time.Now().Add(connections.RotationOverlap)
		actives, err := q.RevokeAllActiveByDeviceServer(ctx, parent.ID)
		if err != nil {
			return fmt.Errorf("active profiles of %v: %w", parent.ID, err)
		}
		touched := make(map[uuid.UUID]bool, len(actives))
		for _, row := range actives {
			superseded, err := q.SupersedeProfile(ctx, db.SupersedeProfileParams{
				ID: row.ID, OverlapValidUntil: &overlap,
			})
			if err != nil {
				return fmt.Errorf("supersede profile %v: %w", row.ID, err)
			}
			// Тот же адрес и тот же срок: ротация ключа не продлевает доступ и не
			// пересаживает клиента на другой адрес.
			child, err := q.InsertProfile(ctx, db.InsertProfileParams{
				ID: uuid.New(), DeviceID: created.ID, ServerID: superseded.ServerID,
				AddressV4: superseded.AddressV4, ExpiresAt: superseded.ExpiresAt,
			})
			if err != nil {
				return fmt.Errorf("insert rotated profile: %w", err)
			}
			oldID, newID := superseded.ID, child.ID
			// Ссылка предка нужна не для порядка, а для желаемого множества:
			// desired set снимает старого пиера только увидев, что у него есть
			// преемник (задача 9).
			if err := q.LinkRotatedProfile(ctx, db.LinkRotatedProfileParams{
				ID: child.ID, RotateFrom: &oldID,
			}); err != nil {
				return fmt.Errorf("link rotated profile %v: %w", child.ID, err)
			}
			if err := q.ReassignAddress(ctx, db.ReassignAddressParams{
				ServerID: superseded.ServerID, Address: superseded.AddressV4,
				OldProfileID: &oldID, NewProfileID: &newID,
			}); err != nil {
				return fmt.Errorf("reassign address %v: %w", superseded.AddressV4, err)
			}
			touched[superseded.ServerID] = true

			detail, err := json.Marshal(map[string]any{"rotated_from": superseded.ID.String()})
			if err != nil {
				return fmt.Errorf("marshal rotation detail: %w", err)
			}
			owner, childDevice := userID, created.ID
			if err := q.InsertConnectionEvent(ctx, db.InsertConnectionEventParams{
				UserID: &owner, DeviceID: &childDevice, ServerID: &superseded.ServerID,
				Event: db.EventTypeProfileIssued, Detail: detail,
			}); err != nil {
				return fmt.Errorf("event rotated profile issued: %w", err)
			}
		}
		// Версия поднимается один раз на затронутый сервер и только если трогать
		// было что: bump без изменения набора пиеров заставил бы узел перечитать
		// то же самое.
		for serverID := range touched {
			if _, err := q.BumpServerConfigVersion(ctx, serverID); err != nil {
				return fmt.Errorf("bump config version of %v: %w", serverID, err)
			}
		}
		// Предок отзывается последним: до этого момента он держит активные профили,
		// и раньше отозвать его значило бы на секунду оставить устройство без
		// ключа, по которому можно понять, что кому принадлежит.
		if err := q.RevokeDevice(ctx, parent.ID); err != nil {
			return fmt.Errorf("revoke parent device: %w", err)
		}
		return nil
	})
	if err != nil {
		return db.Device{}, err
	}
	return created, nil
}
