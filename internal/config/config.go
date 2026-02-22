package config

import (
	"errors"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	DatabaseURL   string
	Issuer        string
	AdminEmail    string
	AdminPassword string
	SessionSecret string
}

func Load() *Config {
	return &Config{
		DatabaseURL:   env("DATABASE_URL", "postgres://transmtf:changeme_in_production@localhost:5432/transmtf_oidc?sslmode=disable"),
		Issuer:        env("ISSUER", "http://localhost:8080"),
		AdminEmail:    env("ADMIN_EMAIL", "contact@transmtf.com"),
		AdminPassword: env("ADMIN_PASSWORD", "changeme_in_production"),
		SessionSecret: env("SESSION_SECRET", "dev_secret_do_not_use_in_prod"),
	}
}

func (c *Config) Validate() error {
	if strings.TrimSpace(c.Issuer) == "" {
		return errors.New("ISSUER is required")
	}
	u, err := url.Parse(c.Issuer)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return errors.New("ISSUER must be an absolute URL, e.g. https://auth.example.com")
	}
	if len(strings.TrimSpace(c.SessionSecret)) < 32 {
		return errors.New("SESSION_SECRET must be at least 32 characters")
	}
	if c.SessionSecret == "dev_secret_do_not_use_in_prod" {
		return errors.New("SESSION_SECRET cannot use default value")
	}
	if c.AdminPassword == "" || c.AdminPassword == "changeme_in_production" {
		return errors.New("ADMIN_PASSWORD must be changed from default")
	}
	if strings.Contains(c.DatabaseURL, "changeme_in_production") && !isLocalIssuer(c.Issuer) {
		return errors.New("DATABASE_URL appears to use default database password")
	}
	return nil
}

func isLocalIssuer(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
