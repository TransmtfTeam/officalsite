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
		return errors.New("必须配置 ISSUER")
	}
	u, err := url.Parse(c.Issuer)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return errors.New("ISSUER 必须是绝对地址，例如 https://auth.example.com")
	}
	if len(strings.TrimSpace(c.SessionSecret)) < 32 {
		return errors.New("SESSION_SECRET 至少需要 32 个字符")
	}
	if c.SessionSecret == "dev_secret_do_not_use_in_prod" {
		return errors.New("SESSION_SECRET 不能使用默认值")
	}
	if c.AdminPassword == "" || c.AdminPassword == "changeme_in_production" {
		return errors.New("ADMIN_PASSWORD 必须修改为非默认值")
	}
	if strings.Contains(c.DatabaseURL, "changeme_in_production") && !isLocalIssuer(c.Issuer) {
		return errors.New("DATABASE_URL 仍在使用默认数据库密码")
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
