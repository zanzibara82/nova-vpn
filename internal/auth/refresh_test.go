package auth

import (
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
)

func TestRefreshTokenEncodingIsReversible(t *testing.T) {
	fam, secret := newFamilyID(), newSecret()
	raw := encodeRefresh(fam, secret)
	parsedFam, parsedSecret, err := parseRefresh(raw)
	if err != nil {
		t.Fatalf("parseRefresh(%q): %v", raw, err)
	}
	if parsedFam != fam || string(parsedSecret) != string(secret) {
		t.Fatal("round-trip lost data")
	}
	// Family-часть обязана быть uuid: на неё ищется семья в БД.
	if _, err := uuid.Parse(parsedFam); err != nil {
		t.Errorf("family part is not a uuid: %v", err)
	}
	if len(parsedSecret) != refreshSecretLen {
		t.Errorf("secret length = %d, want %d", len(parsedSecret), refreshSecretLen)
	}
}

func TestParseRefreshRejectsJunk(t *testing.T) {
	for _, bad := range []string{
		"", "a", "a.b", ".", "###.###",
		base64.URLEncoding.EncodeToString([]byte("not-a-uuid")) + ".AAAAAAAA",
		uuid.NewString() + ".",         // пустой секрет
		uuid.NewString() + ".a.b",      // лишняя часть
		uuid.NewString() + ".AAAAAAA=", // base64url с паддингом — другая каноническая форма
	} {
		if _, _, err := parseRefresh(bad); err == nil {
			t.Errorf("parseRefresh accepted %q", truncate(bad))
		}
	}
}
