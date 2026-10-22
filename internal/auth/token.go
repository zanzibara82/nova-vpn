package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AccessToken struct {
	Value     string
	JTI       string
	ExpiresAt time.Time
}

type Claims struct {
	UserID    uuid.UUID
	JTI       string
	ExpiresAt time.Time
}

type Issuer struct {
	secret []byte
	ttl    time.Duration
	iss    string
}

var ErrInvalidToken = errors.New("access token is invalid")

func NewIssuer(secret []byte, ttl time.Duration) *Issuer {
	if len(secret) < 32 {
		// config.Load уже это проверяет; проверка здесь — защита от прямого вызова
		// (тесты, будущие внутренние команды), а не от пользователя.
		panic("auth: JWT secret must be at least 32 bytes")
	}
	return &Issuer{secret: secret, ttl: ttl, iss: "novavpn-api"}
}

func (i *Issuer) Issue(_ context.Context, userID uuid.UUID) (AccessToken, error) {
	if userID == uuid.Nil {
		return AccessToken{}, errors.New("auth: nil user id")
	}
	now := time.Now()
	exp := now.Add(i.ttl)
	jti := uuid.NewString()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    i.iss,
		Subject:   userID.String(),
		ID:        jti,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(exp),
	}).SignedString(i.secret)
	if err != nil {
		return AccessToken{}, fmt.Errorf("sign access token: %w", err)
	}
	return AccessToken{Value: signed, JTI: jti, ExpiresAt: exp}, nil
}

func (i *Issuer) Parse(value string) (Claims, error) {
	// Ограничение алгоритма на уровне разбора: токен с alg=RS256 или none не
	// проверяется тем же ключом, которым он не подписан.
	tok, err := jwt.ParseWithClaims(value, &jwt.RegisteredClaims{},
		func(*jwt.Token) (any, error) { return i.secret, nil },
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(i.iss),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !tok.Valid {
		return Claims{}, ErrInvalidToken
	}
	rc := tok.Claims.(*jwt.RegisteredClaims)
	userID, err := uuid.Parse(rc.Subject)
	if err != nil || rc.ID == "" {
		return Claims{}, ErrInvalidToken
	}
	if rc.ExpiresAt == nil {
		return Claims{}, ErrInvalidToken
	}
	return Claims{UserID: userID, JTI: rc.ID, ExpiresAt: rc.ExpiresAt.Time}, nil
}
