package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"
)

const (
	EnvDev  = "dev"
	EnvProd = "prod"
)

type Config struct {
	Env         string
	ListenAddr  string
	DatabaseURL string
	RedisAddr   string
	JWTSecret   []byte
	AccessTTL   time.Duration
	RefreshTTL  time.Duration
	// AllowInsecureAPI существует для dev-harness (спецификация §4.4) и жёстко
	// отказывается вне dev — это проверка ТЗ §19.8, а не настройка.
	AllowInsecureAPI bool
}

func Load(getenv func(string) string) (Config, error) {
	c := Config{
		Env:         getenv("NOVAVPN_ENV"),
		ListenAddr:  getenv("NOVAVPN_LISTEN_ADDR"),
		DatabaseURL: getenv("NOVAVPN_DATABASE_URL"),
		RedisAddr:   getenv("NOVAVPN_REDIS_ADDR"),
		AccessTTL:   10 * time.Minute,
		RefreshTTL:  30 * 24 * time.Hour,
	}
	if c.Env == "" {
		return c, errors.New("NOVAVPN_ENV must be dev or prod")
	}
	if c.Env != EnvDev && c.Env != EnvProd {
		return c, fmt.Errorf("NOVAVPN_ENV = %q, want dev|prod", c.Env)
	}
	if c.ListenAddr == "" {
		c.ListenAddr = ":8080"
	}
	if c.DatabaseURL == "" {
		return c, errors.New("NOVAVPN_DATABASE_URL is required")
	}
	if c.RedisAddr == "" {
		return c, errors.New("NOVAVPN_REDIS_ADDR is required")
	}
	secret, err := base64.StdEncoding.DecodeString(getenv("NOVAVPN_JWT_SECRET"))
	if err != nil {
		return c, fmt.Errorf("NOVAVPN_JWT_SECRET: %w", err)
	}
	if len(secret) < 32 {
		return c, fmt.Errorf("NOVAVPN_JWT_SECRET must decode to >= 32 bytes, got %d", len(secret))
	}
	c.JWTSecret = secret
	if v := getenv("NOVAVPN_ACCESS_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 || d > 30*time.Minute {
			return c, fmt.Errorf("NOVAVPN_ACCESS_TTL = %q: want 1s..30m", v)
		}
		c.AccessTTL = d
	}
	if v := getenv("NOVAVPN_REFRESH_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return c, fmt.Errorf("NOVAVPN_REFRESH_TTL = %q", v)
		}
		c.RefreshTTL = d
	}
	insecure, err := strconv.ParseBool(orDefault(getenv("NOVAVPN_ALLOW_INSECURE_API"), "false"))
	if err != nil {
		return c, fmt.Errorf("NOVAVPN_ALLOW_INSECURE_API: %w", err)
	}
	if insecure && c.Env != EnvDev {
		return c, errors.New("insecure API transport is refused outside dev: TLS verification is not optional in prod (NOVAVPN_ALLOW_INSECURE_API)")
	}
	c.AllowInsecureAPI = insecure
	return c, nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
