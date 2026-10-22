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

// Пропущенный параметр в строке хэша не должен превращаться в «тихо посчитали по умолчанию»:
// это путь к проверке пароля с чужими настройками стойкости.
func TestVerifyRejectsMalformedHash(t *testing.T) {
	for _, bad := range []string{
		"", "not-a-hash",
		"$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",     // не argon2id
		"$argon2id$v=19$m=1024,t=3,p=4$c2FsdA$aGFzaA",     // слабый параметр
		"$argon2id$v=19$m=65536,t=3,p=4$!!$aGFzaA",        // мусор в соли
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
