//go:build integration

package integration

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/db"
)

func TestRefreshRotationAndReuse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := db.New(pool(t))
	user := seedUser(t, ctx, q, true)
	svc := auth.NewSessionService(q, auth.NewIssuer(bytes32ForTests(), 10*time.Minute),
		auth.NewRedisDenylist(redisClient(t), slog.New(slog.DiscardHandler)),
		24*time.Hour, slog.New(slog.DiscardHandler))

	first, err := svc.NewSession(ctx, user, nil)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	second, err := svc.Rotate(ctx, first.RefreshToken, nil)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Fatal("rotation returned the same refresh token")
	}
	if second.AccessToken == first.AccessToken {
		t.Fatal("rotation returned the same access token")
	}

	// Переиспользование первого токена → семья отозвана, и второй тоже не работает.
	if _, err := svc.Rotate(ctx, first.RefreshToken, nil); err == nil {
		t.Fatal("reused refresh token accepted")
	}
	if _, err := svc.Rotate(ctx, second.RefreshToken, nil); err == nil {
		t.Fatal("family was not revoked after reuse detection")
	}

	// Отозванный access попадает в denylist: Revoke обязан вызвать Add.
	s3, err := svc.NewSession(ctx, user, nil)
	if err != nil {
		t.Fatalf("NewSession 2: %v", err)
	}
	if err := svc.Revoke(ctx, s3.RefreshToken, ""); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := svc.Rotate(ctx, s3.RefreshToken, nil); err == nil {
		t.Fatal("revoked family still rotates")
	}
}

func TestRevokeAddsAccessJtiToDenylist(t *testing.T) {
	ctx := context.Background()
	q := db.New(pool(t))
	user := seedUser(t, ctx, q, true)
	deny := auth.NewRedisDenylist(redisClient(t), slog.New(slog.DiscardHandler))
	svc := auth.NewSessionService(q, auth.NewIssuer(bytes32ForTests(), 10*time.Minute),
		deny, 24*time.Hour, slog.New(slog.DiscardHandler))
	sess, err := svc.NewSession(ctx, user, nil)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	claims, err := svc.ParseAccess(sess.AccessToken)
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	if err := svc.Revoke(ctx, sess.RefreshToken, sess.AccessToken); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	ok, err := deny.Contains(ctx, claims.JTI)
	if err != nil {
		t.Fatalf("Contains: %v", err)
	}
	if !ok {
		t.Error("logout must add the current access jti to the denylist")
	}
}
