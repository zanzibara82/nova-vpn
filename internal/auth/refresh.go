package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/novavpn/novavpn/internal/db"
)

const refreshSecretLen = 32

var (
	ErrInvalidRefreshToken = errors.New("refresh token is invalid")
	ErrExpiredRefreshToken = errors.New("refresh token expired")
	ErrAccountLocked       = errors.New("account is locked")
)

// refresh-токен непрозрачен, но носит идентификатор семьи: это позволяет
// обнаружить переиспользование, не заводя таблицу истории токенов.
func newFamilyID() string { return uuid.NewString() }

func newSecret() []byte {
	b := make([]byte, refreshSecretLen)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("auth: random secret: %v", err))
	}
	return b
}

var b64 = base64.RawURLEncoding

func encodeRefresh(familyID string, secret []byte) string {
	return familyID + "." + b64.EncodeToString(secret)
}

func parseRefresh(raw string) (string, []byte, error) {
	fam, secretB64, ok := strings.Cut(raw, ".")
	if !ok || fam == "" || secretB64 == "" {
		return "", nil, ErrInvalidRefreshToken
	}
	if _, err := uuid.Parse(fam); err != nil {
		return "", nil, ErrInvalidRefreshToken
	}
	// RawURLEncoding отказывает на любом паддинге → одна каноническая форма секрета.
	secret, err := b64.DecodeString(secretB64)
	if err != nil || len(secret) != refreshSecretLen {
		return "", nil, ErrInvalidRefreshToken
	}
	return fam, secret, nil
}

func hashSecret(secret []byte) []byte {
	sum := sha256.Sum256(secret)
	return sum[:]
}

type Session struct {
	AccessToken      string
	RefreshToken     string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
}

type SessionService struct {
	q          *db.Queries
	iss        *Issuer
	deny       Denylist
	refreshTTL time.Duration
	log        *slog.Logger
}

func NewSessionService(q *db.Queries, iss *Issuer, deny Denylist, refreshTTL time.Duration, log *slog.Logger) *SessionService {
	return &SessionService{q: q, iss: iss, deny: deny, refreshTTL: refreshTTL, log: log}
}

func (s *SessionService) ParseAccess(value string) (Claims, error) { return s.iss.Parse(value) }

func (s *SessionService) NewSession(ctx context.Context, userID uuid.UUID, ip *netip.Addr) (Session, error) {
	fam := newFamilyID()
	secret := newSecret()
	expires := time.Now().Add(s.refreshTTL)
	if _, err := s.q.InsertRefreshFamily(ctx, db.InsertRefreshFamilyParams{
		ID: uuid.MustParse(fam), UserID: userID, CurrentTokenHash: hashSecret(secret),
		ExpiresAt: expires, Ip: ip,
	}); err != nil {
		return Session{}, fmt.Errorf("create refresh family: %w", err)
	}
	return s.mint(ctx, userID, fam, secret, expires)
}

// Rotate меняет секрет семьи. Старый секрет перестаёт быть текущим, и любое его
// повторное предъявление уходит в ветку переиспользования.
func (s *SessionService) Rotate(ctx context.Context, raw string, ip *netip.Addr) (Session, error) {
	fam, secret, err := parseRefresh(raw)
	if err != nil {
		return Session{}, err
	}
	family, err := s.q.RefreshByID(ctx, uuid.MustParse(fam))
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrInvalidRefreshToken
	}
	if err != nil {
		return Session{}, fmt.Errorf("load refresh family: %w", err)
	}
	if family.RevokedAt != nil {
		// Семья уже сожжена; повторный вход тем же токеном — тоже сигнал.
		return Session{}, ErrInvalidRefreshToken
	}
	if time.Now().After(family.ExpiresAt) {
		reason := "expired"
		_ = s.q.RevokeRefreshFamily(ctx, db.RevokeRefreshFamilyParams{ID: family.ID, RevokeReason: &reason})
		return Session{}, ErrExpiredRefreshToken
	}
	if subtle.ConstantTimeCompare(family.CurrentTokenHash, hashSecret(secret)) != 1 {
		// Секрет не текущий, а семья живая → этот токен уже поменяли. Отзываем всех.
		reason := "reuse_detected"
		if err := s.q.RevokeRefreshFamily(ctx, db.RevokeRefreshFamilyParams{ID: family.ID, RevokeReason: &reason}); err != nil {
			s.log.Error("revoke family on reuse", "err", err)
		}
		s.log.Warn("refresh token reuse detected, family revoked", "user_id", family.UserID)
		return Session{}, ErrInvalidRefreshToken
	}
	user, err := s.q.UserByID(ctx, family.UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrInvalidRefreshToken
	}
	if err != nil {
		return Session{}, fmt.Errorf("load user for rotation: %w", err)
	}
	if user.Status != db.UserStatusActive {
		return Session{}, ErrAccountLocked
	}
	next := newSecret()
	rotated, err := s.q.RotateRefresh(ctx, db.RotateRefreshParams{
		ID: family.ID, NewHash: hashSecret(next), OldHash: hashSecret(secret), Ip: ip,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// Условие current_token_hash = $3 не прошло: конкурентная ротация уже состоялась.
		return Session{}, ErrInvalidRefreshToken
	}
	if err != nil {
		return Session{}, fmt.Errorf("rotate refresh: %w", err)
	} // rotated.UserID — тот же пользователь, что и у семьи: mint подписывает access
	// на субъекта, а не на идентификатор семьи.
	return s.mint(ctx, rotated.UserID, fam, next, family.ExpiresAt)
}

// Revoke отзывает семью. access передаётся, когда его надо вынять из оборота
// немедленно (logout); при отзыве снаружи активный access доживает не дольше TTL —
// см. спецификацию §5.3.
func (s *SessionService) Revoke(ctx context.Context, raw, access string) error {
	fam, _, err := parseRefresh(raw)
	if err != nil {
		return err
	}
	if access != "" {
		if cl, err := s.iss.Parse(access); err == nil {
			if err := s.deny.Add(ctx, cl.JTI, cl.ExpiresAt); err != nil {
				s.log.Warn("denylist add failed", "err", err)
			}
		}
		// Невалидный access не блокирует отзыв семьи: logout обязан сработать и
		// когда клиент принёс просроченный access.
	}
	reason := "logout"
	return s.q.RevokeRefreshFamily(ctx, db.RevokeRefreshFamilyParams{
		ID: uuid.MustParse(fam), RevokeReason: &reason,
	})
}

func (s *SessionService) mint(ctx context.Context, userID uuid.UUID, fam string, secret []byte, refreshExp time.Time) (Session, error) {
	access, err := s.iss.Issue(ctx, userID)
	if err != nil {
		return Session{}, err
	}
	return Session{
		AccessToken:      access.Value,
		RefreshToken:     encodeRefresh(fam, secret),
		AccessExpiresAt:  access.ExpiresAt,
		RefreshExpiresAt: refreshExp,
	}, nil
}
