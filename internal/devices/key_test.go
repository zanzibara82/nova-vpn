package devices

import (
	"encoding/base64"
	"strings"
	"testing"
)

// 32 байта нулей → канонический ключ из 43 'A' и '='.
const canonicalZeros = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestParseCanonicalKey(t *testing.T) {
	k, err := ParsePublicKey(canonicalZeros)
	if err != nil {
		t.Fatalf("canonical key rejected: %v", err)
	}
	if k != [32]byte{} {
		t.Fatalf("decoded key = %x", k)
	}
}

// 256 бит не делятся на 6: у последнего символа 2 spare-бита, и они обязаны быть нулём.
// 'A'→'B' выставляет бит — base64-декодер Go это молча проглатывает, поэтому
// повторное кодирование и есть проверка каноничности (спецификация §5.2).
func TestRejectsNonCanonicalLastChar(t *testing.T) {
	non := canonicalZeros[:42] + "B="
	if _, err := ParsePublicKey(non); err != ErrKeyNotCanonical {
		t.Fatalf("err = %v, want ErrKeyNotCanonical", err)
	}
	// Тот же трюк на предпоследнем символе: spare-битов нет, ключ валиден.
	if _, err := ParsePublicKey(canonicalZeros[:41] + "B" + canonicalZeros[42:]); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
}

func TestRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"", "   ", "not-base64-!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!=",
		canonicalZeros[:42],  // без '=' → длина 43
		canonicalZeros + "=", // длина 45
		strings.ToLower(canonicalZeros),
		base64.URLEncoding.EncodeToString(make([]byte, 32)) + "==", // url-safe форма
	} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestRejectsNewlineAndWhitespaceInside(t *testing.T) {
	// Ключ с переносом строки — классика «пропустили из буфера обмена»:
	// проверка длины обязана отработать раньше декодирования — вход с переносом
	// длиннее 44 символов.
	if _, err := ParsePublicKey(canonicalZeros[:20] + "\n" + canonicalZeros[20:]); err == nil {
		t.Fatal("key with newline accepted")
	}
}

func TestValidPlatform(t *testing.T) {
	for _, ok := range []string{"android", "ios", "windows", "macos", "linux", "other"} {
		if !ValidPlatform(ok) {
			t.Errorf("platform %q rejected", ok)
		}
	}
	for _, bad := range []string{"", "Android", "android ", "iphone", "WINDOWS"} {
		if ValidPlatform(bad) {
			t.Errorf("platform %q accepted", bad)
		}
	}
}
