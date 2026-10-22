package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// Параметры — OWASP argon2id: 64 MiB, 3 прохода, 4 потока.
	// Меньше — дешевле брутфорс; больше — узел падает на малой RAM при всплеске логина.
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16

	MinPasswordLen = 10
	MaxPasswordLen = 1024
)

var (
	ErrWeakPassword = errors.New("password is too short or too long")
	phcPrefix       = "$argon2id$v=19$"
)

func HashPassword(password string) (string, error) {
	if len(password) < MinPasswordLen || len(password) > MaxPasswordLen {
		return "", ErrWeakPassword
	}
	// MinPasswordLen считается в байтах: для UTF-8 это нижняя граница, а не «10 символов».
	// Увеличивать без замера стоимости проверки на целевом узле нельзя.
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("%sm=%d,t=%d,p=%d$%s$%s",
		phcPrefix, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword возвращает false на любом malformed-хэше, не паникуя и не
// подставляя параметры по умолчанию.
func VerifyPassword(phc, password string) bool {
	if !strings.HasPrefix(phc, phcPrefix) || len(password) < MinPasswordLen || len(password) > MaxPasswordLen {
		return false
	}
	rest := strings.TrimPrefix(phc, phcPrefix)
	parts := strings.Split(rest, "$")
	if len(parts) != 3 {
		return false
	}
	var m, t, p uint32
	if _, err := fmt.Sscanf(parts[0], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	if m < argonMemory || t < argonTime || p == 0 || p > 8 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil || len(salt) < 8 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(want) < 16 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, uint8(p), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
