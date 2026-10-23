package devices

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

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
// Чужой устройство отдаётся той же ошибкой, что и несуществующий, чтобы не строить
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
