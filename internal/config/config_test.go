package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func valid() map[string]string {
	return map[string]string{
		"NOVAVPN_ENV":          "dev",
		"NOVAVPN_DATABASE_URL": "postgres://nova:nova@localhost:5432/nova?sslmode=disable",
		"NOVAVPN_REDIS_ADDR":   "localhost:6379",
		"NOVAVPN_JWT_SECRET":   "dj2u6QzU1TgZ0yQxT1dHQ0h6T0ZObDNnNXE3czE1VDZlcTV6M3E9", // 32 б, base64
	}
}

func TestLoadAcceptsDevDefaults(t *testing.T) {
	c, err := Load(env(valid()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.AccessTTL != 10*time.Minute {
		t.Errorf("AccessTTL = %v, want 10m", c.AccessTTL)
	}
	if c.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q", c.ListenAddr)
	}
}

func TestInsecureAPIRefusedOutsideDev(t *testing.T) {
	m := valid()
	m["NOVAVPN_ENV"] = "prod"
	m["NOVAVPN_ALLOW_INSECURE_API"] = "1"
	_, err := Load(env(m))
	if err == nil || !strings.Contains(err.Error(), "insecure") {
		t.Fatalf("prod+insecure must be refused, got %v", err)
	}
}

func TestJWTSecretMustBe32Bytes(t *testing.T) {
	m := valid()
	m["NOVAVPN_JWT_SECRET"] = "c2hvcnQ=" // 5 байт
	if _, err := Load(env(m)); err == nil {
		t.Fatal("short JWT secret accepted")
	}
}
