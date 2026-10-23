package connections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/novavpn/novavpn/internal/db"
	"github.com/novavpn/novavpn/internal/entitlements"
)

// DefaultProfileTTL — потолок жизни профиля без подписки-ограничителя. Спецификация
// §7.1 говорит «выдать профиль», но не говорит, на сколько: 30 суток — решение A-2,
// и оно в одной константе. Смысл числа: профиль переживает обычный перезапуск клиента,
// но не переживает молчаливо забытую подписку.
const DefaultProfileTTL = 30 * 24 * time.Hour

// ProfileExpiry — профиль не может жить дольше права, которое его выдало.
// Два места, решающих «когда кончится доступ», обязательно разошлись бы, поэтому
// источник истины один: ends_at подписки (задача 4 перенёс её в Entitlement).
func ProfileExpiry(ent entitlements.Entitlement, now time.Time) time.Time {
	expiry := now.Add(DefaultProfileTTL)
	if ent.EndsAt != nil && ent.EndsAt.Before(expiry) {
		return *ent.EndsAt
	}
	return expiry
}

// RotationOverlap — окно, в котором узел держит и старый, и новый ключ (спецификация
// §7.3). Число объявлено один раз здесь, а не по месту в devices и в servers: расхождение
// двух копий рвёт соединение — предок снимется раньше, чем клиент поднимет новый ключ.
const RotationOverlap = 10 * time.Minute

// ошибки-стражи и порядок проверок задаёт план, задача 5 шаг 2: последовательность
// «устройство → его владелец → срок права → сервер → выдача» менять нельзя, потому что
// более ранний отказ отвечает раньше и не даёт дойти до того, что человек мог бы
// увидеть как подсказку о чужом устройстве.
var (
	ErrForbiddenDevice    = errors.New("connections: устройство принадлежит другому пользователю или не существует")
	ErrDeviceRevoked      = errors.New("connections: устройство отозвано")
	ErrNoSubscription     = errors.New("connections: активной подписки нет")
	ErrServerUnknown      = errors.New("connections: сервер не найден")
	ErrServerNotAvailable = errors.New("connections: сервер не готов принимать новые профили")
	ErrAlreadyActive      = errors.New("connections: на этом сервере уже есть активный профиль устройства")
	ErrNotActive          = errors.New("connections: активного профиля у этой пары нет")
)

// issueAttempts — сколько раз выдача повторяется целиком при гонке занятия адреса.
// Три: это не отступ перед конфликтом, а попытка разойтись с тем, кто обошёл
// блокировку; на четвёртом отказ отдаётся клиенту как есть.
const issueAttempts = 3

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// Service — выдача и отзыв профилей. Держит и пул, и Queries: чтения (устройство,
// сервер, список) идут поверх пула без транзакции, а всё, что меняет набор пиеров,
// обязано идти через пул же, потому что транзакция собирается в db.RunInTx.
type Service struct {
	pool *pgxpool.Pool
	q    *db.Queries
	ent  *entitlements.Service
}

func NewService(pool *pgxpool.Pool, ent *entitlements.Service) *Service {
	return &Service{pool: pool, q: db.New(pool), ent: ent}
}

// ownedDevice — проверка владельца без оракула: несуществующее и чужое устройство
// отвечают одним и тем же ошибочным стражем, иначе по различию ответов можно
// перебирать идентификаторы чужих устройств.
func (s *Service) ownedDevice(ctx context.Context, deviceID, userID uuid.UUID) (db.Device, error) {
	d, err := s.q.DeviceByID(ctx, deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return db.Device{}, ErrForbiddenDevice
	}
	if err != nil {
		return db.Device{}, fmt.Errorf("connections: устройство %v: %w", deviceID, err)
	}
	if d.UserID != userID {
		return db.Device{}, ErrForbiddenDevice
	}
	return d, nil
}

// issueDetail — содержимое события profile_issued. Только коды и версии: про трафик,
// объёмы и что-либо похожее на содержимое туннеля здесь не появляется ничего (ТЗ §11).
type issueDetail struct {
	ServerID  uuid.UUID `json:"server_id"`
	Address   string    `json:"address"`
	ExpiresAt time.Time `json:"expires_at"`
}

type revokeDetail struct {
	ServerID uuid.UUID `json:"server_id"`
	Address  string    `json:"address"`
}

// Issue выдаёт профиль устройства на сервер. Порядок проверок = §7.1.
//
// Срок считается до транзакции, потому что он берётся из подписки, а подписку читать
// внутри транзакции выдачи незачем. Из этого следует ограничение, которое легче всего
// «забыть»: подписка, истёкшая между проверкой и вставкой, остаётся действующей на весь
// TTL профиля. Оно осознанное (§13), а не дыра: отзыв подписки доживает до
// sweeper-прохода задачи 13, а не до каждого запроса.
func (s *Service) Issue(ctx context.Context, userID, deviceID, serverID uuid.UUID) (db.VpnProfile, error) {
	d, err := s.ownedDevice(ctx, deviceID, userID)
	if err != nil {
		return db.VpnProfile{}, err
	}
	if d.RevokedAt != nil {
		return db.VpnProfile{}, ErrDeviceRevoked
	}
	ent, err := s.ent.ForUser(ctx, userID)
	if errors.Is(err, entitlements.ErrNoActiveSubscription) {
		return db.VpnProfile{}, ErrNoSubscription
	}
	if err != nil {
		return db.VpnProfile{}, err
	}
	srv, err := s.q.ServerByID(ctx, serverID)
	if errors.Is(err, pgx.ErrNoRows) {
		return db.VpnProfile{}, ErrServerUnknown
	}
	if err != nil {
		return db.VpnProfile{}, fmt.Errorf("connections: сервер %v: %w", serverID, err)
	}
	// Буквально «online»: draining ещё работает и отдаёт трафик сидящим, но нового
	// клиента принимать не должен — он получил бы туннель, который через минуту опустеет.
	if srv.MaintenanceStatus != db.MaintenanceStatusOnline {
		return db.VpnProfile{}, ErrServerNotAvailable
	}
	expiresAt := ProfileExpiry(ent, time.Now())

	var profile db.VpnProfile
	for attempt := 1; ; attempt++ {
		err := db.RunInTx(ctx, s.pool, func(q *db.Queries) error {
			addr, err := Allocate(ctx, q, srv)
			if err != nil {
				return err
			}
			created, err := q.InsertProfile(ctx, db.InsertProfileParams{
				ID: uuid.New(), DeviceID: deviceID, ServerID: serverID,
				AddressV4: addr, ExpiresAt: expiresAt,
			})
			if err != nil {
				// Гонка двух параллельных выдач на пару (устройство, сервер), а не
				// «неизвестная ошибка БД»: уникальность держит индекс из 0002, и
				// признание её здесь дешевле, чем разбор состояния после отказа.
				if isUniqueViolation(err) {
					return ErrAlreadyActive
				}
				return fmt.Errorf("connections: вставка профиля: %w", err)
			}
			if err := Claim(ctx, q, srv, addr, created.ID); err != nil {
				return err
			}
			if _, err := q.BumpServerConfigVersion(ctx, serverID); err != nil {
				return fmt.Errorf("connections: версия конфига сервера %v: %w", serverID, err)
			}
			if err := insertIssuedEvent(ctx, q, issueDetail{
				ServerID: serverID, Address: addr.String(), ExpiresAt: expiresAt,
			}, userID, deviceID); err != nil {
				return err
			}
			profile = created
			return nil
		})
		if err == nil {
			return profile, nil
		}
		if errors.Is(err, ErrAddressRace) && attempt < issueAttempts {
			continue
		}
		return db.VpnProfile{}, err
	}
}

func insertIssuedEvent(ctx context.Context, q *db.Queries, detail issueDetail,
	userID, deviceID uuid.UUID) error {
	body, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("connections: detail события выдачи: %w", err)
	}
	if err := q.InsertConnectionEvent(ctx, db.InsertConnectionEventParams{
		UserID: &userID, DeviceID: &deviceID, ServerID: &detail.ServerID,
		Event: db.EventTypeProfileIssued, Detail: body,
	}); err != nil {
		return fmt.Errorf("connections: событие выдачи: %w", err)
	}
	return nil
}

// Revoke отзывает активный профиль пары и освобождает адрес. Возвращает прочитанную
// после отзыва строку, а не то, что было прочитано до: handler из этого ничего не
// печатает, зато тест доказывает адрес и статус настоящим состоянием базы, а не
// обещанием.
//
// Окно переиспользования (§7.2) задаёт SQL задачи 1, а не Go: два места с одним
// числом обязательно разошлись бы, и первым бы солгал тот, что стоит дальше от теста.
func (s *Service) Revoke(ctx context.Context, userID, deviceID, serverID uuid.UUID) (db.VpnProfile, error) {
	if _, err := s.ownedDevice(ctx, deviceID, userID); err != nil {
		return db.VpnProfile{}, err
	}
	active, err := s.q.ActiveProfileByDeviceServer(ctx, db.ActiveProfileByDeviceServerParams{
		DeviceID: deviceID, ServerID: serverID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return db.VpnProfile{}, ErrNotActive
	}
	if err != nil {
		return db.VpnProfile{}, fmt.Errorf("connections: активный профиль пары %v/%v: %w",
			deviceID, serverID, err)
	}

	var revoked db.VpnProfile
	err = db.RunInTx(ctx, s.pool, func(q *db.Queries) error {
		row, err := q.RevokeProfile(ctx, active.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			// Профиль успели отозвать между чтением и этой транзакцией.
			return ErrNotActive
		}
		if err != nil {
			return fmt.Errorf("connections: отзыв профиля %v: %w", active.ID, err)
		}
		profileID := row.ID
		if err := q.ReleaseAddressByProfile(ctx, &profileID); err != nil {
			return fmt.Errorf("connections: освобождение адреса %v: %w", row.AddressV4, err)
		}
		if _, err := q.BumpServerConfigVersion(ctx, serverID); err != nil {
			return fmt.Errorf("connections: версия конфига сервера %v: %w", serverID, err)
		}
		body, err := json.Marshal(revokeDetail{ServerID: serverID, Address: row.AddressV4.String()})
		if err != nil {
			return fmt.Errorf("connections: detail события отзыва: %w", err)
		}
		if err := q.InsertConnectionEvent(ctx, db.InsertConnectionEventParams{
			UserID: &userID, DeviceID: &deviceID, ServerID: &serverID,
			Event: db.EventTypeProfileRevoked, Detail: body,
		}); err != nil {
			return fmt.Errorf("connections: событие отзыва: %w", err)
		}
		latest, err := q.ProfileByID(ctx, row.ID)
		if err != nil {
			return fmt.Errorf("connections: чтение отозванного профиля %v: %w", row.ID, err)
		}
		revoked = latest
		return nil
	})
	if err != nil {
		return db.VpnProfile{}, err
	}
	return revoked, nil
}

// List — профили устройства. Проверка владельца здесь, а не «вызывающий handler
// проверил»: сервис вызывается и из задач 6..13, и из тестов, и одно забытое
// проверка превращается в чтение чужих адресов.
func (s *Service) List(ctx context.Context, userID, deviceID uuid.UUID) ([]db.VpnProfile, error) {
	if _, err := s.ownedDevice(ctx, deviceID, userID); err != nil {
		return nil, err
	}
	list, err := s.q.ProfilesByDevice(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("connections: профили устройства %v: %w", deviceID, err)
	}
	return list, nil
}

// Profile — последний профиль пары, включая отозванный: человек имеет право видеть,
// что с его доступом случилось. «Профиля не было никогда» и «профиль не активен»
// отвечают одним стражем: различие не влияет ни на одно действие клиента, а как
// оракул о существовании пары оно работать будет.
func (s *Service) Profile(ctx context.Context, userID, deviceID, serverID uuid.UUID) (db.VpnProfile, error) {
	if _, err := s.ownedDevice(ctx, deviceID, userID); err != nil {
		return db.VpnProfile{}, err
	}
	p, err := s.q.LatestProfileByDeviceServer(ctx, db.LatestProfileByDeviceServerParams{
		DeviceID: deviceID, ServerID: serverID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return db.VpnProfile{}, ErrNotActive
	}
	if err != nil {
		return db.VpnProfile{}, fmt.Errorf("connections: профиль пары %v/%v: %w",
			deviceID, serverID, err)
	}
	return p, nil
}

// ConfigText собирает клиентский конфиг. Право на текст имеет только активный и
// непросроченный профиль: superseded внутри окна overlap не отдаётся никогда, потому
// что второй текст со старым ключом в ответе — это способ молча вернуть соединение
// на предка, из которого клиент уже вышел.
func (s *Service) ConfigText(ctx context.Context, userID, deviceID, serverID uuid.UUID) (string, error) {
	if _, err := s.ownedDevice(ctx, deviceID, userID); err != nil {
		return "", err
	}
	prof, err := s.q.ActiveProfileByDeviceServer(ctx, db.ActiveProfileByDeviceServerParams{
		DeviceID: deviceID, ServerID: serverID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotActive
	}
	if err != nil {
		return "", fmt.Errorf("connections: активный профиль пары %v/%v: %w", deviceID, serverID, err)
	}
	// Статус просроченного профиля обновляет sweeper (задача 13), поэтому между
	// окончанием срока и его прогоном строка лежит активной. Проверка срока здесь, а
	// не только в sweeper'е: выдать конфиг просроченному профилю значило бы отдать
	// доступ без права.
	if !prof.ExpiresAt.After(time.Now()) {
		return "", ErrNotActive
	}
	srv, err := s.q.ServerByID(ctx, serverID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrServerUnknown
	}
	if err != nil {
		return "", fmt.Errorf("connections: сервер %v: %w", serverID, err)
	}
	text, err := Render(srv, prof.AddressV4)
	if err != nil {
		return "", fmt.Errorf("connections: сборка конфига для %v: %w", prof.AddressV4, err)
	}
	return text, nil
}
