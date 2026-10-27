//go:build integration

package main

import (
	"context"
	"encoding/base64"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/novavpn/novavpn/internal/auth"
	"github.com/novavpn/novavpn/internal/db"
)

func cliEnv(t *testing.T) func(string) string {
	t.Helper()
	databaseURL := os.Getenv("NOVAVPN_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("NOVAVPN_DATABASE_URL is not set; run `make up-dev` first")
	}
	values := map[string]string{
		"NOVAVPN_ENV":          "dev",
		"NOVAVPN_DATABASE_URL": databaseURL,
		"NOVAVPN_REDIS_ADDR":   "127.0.0.1:6379",
		// Ровно 32 байта после декодирования: config.Load отказывает меньшему.
		"NOVAVPN_JWT_SECRET": base64.StdEncoding.EncodeToString([]byte("cli-integration-secret-32-bytes!")),
	}
	return func(key string) string { return values[key] }
}

var cliTestPool *pgxpool.Pool

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if cliTestPool == nil {
		p, err := db.Pool(context.Background(), os.Getenv("NOVAVPN_DATABASE_URL"))
		if err != nil {
			t.Fatalf("pool: %v", err)
		}
		cliTestPool = p
	}
	return cliTestPool
}

func countAdmins(t *testing.T, email string) int {
	t.Helper()
	var n int
	if err := testPool(t).QueryRow(context.Background(),
		"SELECT count(*) FROM admin_users WHERE email = $1", email).Scan(&n); err != nil {
		t.Fatalf("count admins: %v", err)
	}
	return n
}

// captureOutput подменяет os.Stdout на трубу: без этого «id и email на stdout»
// проверялось бы кодом, а не тем, что увидит оператор.
func captureOutput(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	runErr := fn()
	os.Stdout = old
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	return string(out), runErr
}

func stdinBytes(password string) func() ([]byte, error) {
	return func() ([]byte, error) { return []byte(password), nil }
}

func TestAdminCLICreateRequiresEmail(t *testing.T) {
	getenv := cliEnv(t)
	for _, args := range [][]string{{"admin"}, {"admin", "create"}} {
		err := run(args, getenv, stdinBytes("cli-admin-password-1\n"))
		if err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("run(%q) = %v, want usage error", args, err)
		}
	}
}

func TestAdminCLICreateRejectsShortPassword(t *testing.T) {
	getenv := cliEnv(t)
	email := "cli-short-" + uuid.NewString()[:8] + "@novavpn.test"
	err := run([]string{"admin", "create", email}, getenv, stdinBytes("short\n"))
	if err == nil {
		t.Fatal("короткий пароль принят")
	}
	if n := countAdmins(t, email); n != 0 {
		t.Errorf("админов с %s = %d, want 0: до базы дело доходить не должно", email, n)
	}
}

func TestAdminCLICreateWritesAdmin(t *testing.T) {
	getenv := cliEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	email := "cli-" + uuid.NewString()[:8] + "@novavpn.test"
	const password = "cli-admin-password-1"

	out, err := captureOutput(t, func() error {
		return run([]string{"admin", "create", email}, getenv, stdinBytes(password+"\n"))
	})
	if err != nil {
		t.Fatalf("создание админа: %v", err)
	}

	q := db.New(testPool(t))
	row, err := q.AdminByEmail(ctx, email)
	if err != nil {
		t.Fatalf("админ не записан: %v", err)
	}
	if row.Email != email {
		t.Errorf("email = %q, want %q", row.Email, email)
	}
	if !auth.VerifyPassword(row.PasswordHash, password) {
		t.Error("записанный хеш не подтверждает поданный пароль")
	}
	if !strings.Contains(out, row.ID.String()) || !strings.Contains(out, email) {
		t.Errorf("stdout = %q, want id %s и email %s", out, row.ID, email)
	}
	if strings.Contains(out, password) {
		t.Error("stdout содержит пароль")
	}

	// Повтор с тем же email: скрипт раскатки обязан увидеть провал, а не 0.
	out, err = captureOutput(t, func() error {
		return run([]string{"admin", "create", email}, getenv, stdinBytes("another-admin-password-1\n"))
	})
	if err == nil {
		t.Fatal("дубликат email принят")
	}
	if !strings.Contains(err.Error(), "уже есть") {
		t.Errorf("сообщение об отказе = %q, want упоминание существующего админа", err)
	}
	if out != "" {
		t.Errorf("при отказе что-то напечатано в stdout: %q", out)
	}
	if n := countAdmins(t, email); n != 1 {
		t.Errorf("админов с %s = %d, want 1", email, n)
	}
}
