package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newTestIssuer(t *testing.T) *Issuer {
	t.Helper()
	return NewIssuer(bytes32("jwt-secret-for-tests-000000000000"), 10*time.Minute)
}

func bytes32(s string) []byte {
	b := make([]byte, 32)
	copy(b, s)
	return b
}

func TestIssueAndParseRoundTrip(t *testing.T) {
	iss := newTestIssuer(t)
	user := uuid.New()
	tok, err := iss.Issue(context.Background(), user)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !strings.HasPrefix(tok.Value, "eyJ") {
		t.Fatalf("access token is not a JWT: %q", tok.Value)
	}
	if _, err := uuid.Parse(tok.JTI); err != nil {
		t.Fatalf("jti is not a uuid: %q", tok.JTI)
	}
	if tok.ExpiresAt.Before(time.Now().Add(9 * time.Minute)) {
		t.Fatalf("TTL too short: %v", tok.ExpiresAt)
	}
	cl, err := iss.Parse(tok.Value)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cl.UserID != user || cl.JTI != tok.JTI {
		t.Errorf("claims mismatch: %+v", cl)
	}
}

func TestParseRejectsForeignSignature(t *testing.T) {
	good := newTestIssuer(t)
	tok, _ := good.Issue(context.Background(), uuid.New())
	bad := NewIssuer(bytes32("a-completely-different-secret!!!"), 10*time.Minute)
	if _, err := bad.Parse(tok.Value); err == nil {
		t.Fatal("token from another secret accepted")
	}
}

func TestParseRejectsExpiredAndWrongAlg(t *testing.T) {
	expired := NewIssuer(bytes32("jwt-secret-for-tests-000000000000"), time.Millisecond)
	tok, err := expired.Issue(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := expired.Parse(tok.Value); err == nil {
		t.Error("expired token accepted")
	}
	// Токен с alg=none (классическая подмена): подпись не должна «проходить по инерции».
	if _, err := expired.Parse("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0."); err == nil {
		t.Error("alg=none token accepted")
	}
}

func TestIssueRefusesEmptyUserID(t *testing.T) {
	if _, err := newTestIssuer(t).Issue(context.Background(), uuid.Nil); err == nil {
		t.Fatal("nil user id issued a token")
	}
}

func TestAdminAndUserIssuersRejectEachOther(t *testing.T) {
	secret := bytes32("shared-secret-for-issuer-split-test")
	user := NewIssuer(secret, 10*time.Minute)
	admin := NewAdminIssuer(secret, 10*time.Minute)

	uc, err := user.Issue(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("user issue: %v", err)
	}
	ac, err := admin.Issue(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("admin issue: %v", err)
	}

	if _, err := admin.Parse(uc.Value); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("admin issuer accepted a user token: %v", err)
	}
	if _, err := user.Parse(ac.Value); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("user issuer accepted an admin token: %v", err)
	}
	// Обратная проверка: свой токен обязан проходить, иначе две проверки выше проходили бы «на пустоте».
	if _, err := admin.Parse(ac.Value); err != nil {
		t.Errorf("admin issuer rejected its own token: %v", err)
	}
	if _, err := user.Parse(uc.Value); err != nil {
		t.Errorf("user issuer rejected its own token: %v", err)
	}
}
