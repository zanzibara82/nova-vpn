package auth

import (
	"regexp"
	"strings"
	"testing"
)

var phc = regexp.MustCompile(`^\$argon2id\$v=19\$m=65536,t=3,p=4\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$`)

func TestHashProducesVerifiablePHC(t *testing.T) {
	h, err := HashPassword("корректный-пароль-длинный")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !phc.MatchString(h) {
		t.Fatalf("hash is not the documented PHC form: %q", h)
	}
	if !VerifyPassword(h, "корректный-пароль-длинный") {
		t.Fatal("correct password rejected")
	}
	if VerifyPassword(h, "корректный-пароль-длинны") {
		t.Fatal("wrong password accepted")
	}
}

func TestHashIsSalted(t *testing.T) {
	a, _ := HashPassword("same-password-12345")
	b, _ := HashPassword("same-password-12345")
	if a == b {
		t.Fatal("two hashes of the same password are identical — salt is missing or fixed")
	}
}

func TestRejectsEmptyAndShort(t *testing.T) {
	for _, pw := range []string{"", "short", strings.Repeat("x", MaxPasswordLen+1)} {
		if _, err := HashPassword(pw); err == nil {
			t.Errorf("HashPassword(%q) accepted", truncate(pw))
		}
	}
}

// Контракт объявляет minLength/maxLength в code points. Байтовый счёт пропускал
// кириллический пароль из шести символов (12 байт) и отвергал допустимые 1024.
func TestPasswordLengthCountsCodePoints(t *testing.T) {
	short := strings.Repeat("я", MinPasswordLen-1)
	if _, err := HashPassword(short); err == nil {
		t.Fatalf("HashPassword(%d символов, %d байт) принят", MinPasswordLen-1, len(short))
	}
	ok := strings.Repeat("я", MinPasswordLen)
	h, err := HashPassword(ok)
	if err != nil {
		t.Fatalf("HashPassword(%d символов, %d байт): %v", MinPasswordLen, len(ok), err)
	}
	if !VerifyPassword(h, ok) {
		t.Fatal("пароль на нижней границе не подтвердился")
	}
	if VerifyPassword(h, strings.Repeat("я", MinPasswordLen-1)) {
		t.Fatal("пароль короче нижней границы принят при проверке")
	}
	if _, err := HashPassword(strings.Repeat("я", MaxPasswordLen+1)); err == nil {
		t.Error("HashPassword принял пароль длиннее верхней границы")
	}
}

// Пропущенный параметр в строке хэша не должен превращаться в «тихо посчитали по умолчанию»:
// это путь к проверке пароля с чужими настройками стойкости.
func TestVerifyRejectsMalformedHash(t *testing.T) {
	for _, bad := range []string{
		"", "not-a-hash",
		"$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA", // не argon2id
		"$argon2id$v=19$m=1024,t=3,p=4$c2FsdA$aGFzaA", // слабый параметр
		"$argon2id$v=19$m=65536,t=3,p=4$!!$aGFzaA",    // мусор в соли
	} {
		if VerifyPassword(bad, "anything-long-enough") {
			t.Errorf("VerifyPassword accepted %q", truncate(bad))
		}
	}
}

func truncate(s string) string {
	if len(s) > 24 {
		return s[:24] + "…"
	}
	return s
}
