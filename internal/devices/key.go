package devices

import (
	"encoding/base64"
	"errors"
)

const keyLen = 32

var (
	ErrKeyLength       = errors.New("wireguard public key must be 32 bytes")
	ErrKeyNotBase64    = errors.New("wireguard public key is not valid base64")
	ErrKeyNotCanonical = errors.New("wireguard public key is not canonical base64")
)

// platform — значение из ENUM device_platform (миграция 0001). Сверка здесь даёт
// 400 вместо 500 от БД; оба списка обязаны быть синхронны, и тест
// TestValidPlatform покрывает эту синхронизацию.
var platforms = map[string]struct{}{
	"android": {}, "ios": {}, "windows": {}, "macos": {}, "linux": {}, "other": {},
}

func ValidPlatform(s string) bool {
	_, ok := platforms[s]
	return ok
}

// ParsePublicKey принимает только канонический std-base64 публичного ключа.
// Повторное кодирование — не косметика: Go-декодер не смотрит на spare-биты, и
// два разных входа дали бы один и тот же ключ, а UNIQUE(user_id, public_key)
// в БД сравнивает строки.
func ParsePublicKey(b64 string) ([32]byte, error) {
	var out [32]byte
	if len(b64) != 44 || b64[43] != '=' {
		return out, ErrKeyLength
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return out, ErrKeyNotBase64
	}
	if len(raw) != keyLen {
		return out, ErrKeyLength
	}
	if base64.StdEncoding.EncodeToString(raw) != b64 {
		return out, ErrKeyNotCanonical
	}
	copy(out[:], raw)
	return out, nil
}
