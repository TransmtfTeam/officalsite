package main

import (
	"context"
	"embed"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"transmtf.com/oidc/internal/config"
	"transmtf.com/oidc/internal/crypto"
	"transmtf.com/oidc/internal/server"
	"transmtf.com/oidc/internal/store"
)

//go:embed web/templates/*.html
var templateFS embed.FS

//go:embed web/static
var staticFS embed.FS

func main() {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	db, err := store.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("connect db: %v", err)
	}
	st := store.New(db)

	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	if err := st.EnsureDefaults(ctx); err != nil {
		log.Fatalf("ensure defaults: %v", err)
	}

	if cfg.AdminEmail != "" && cfg.AdminPassword != "" {
		if err := st.EnsureAdmin(ctx, cfg.AdminEmail, cfg.AdminPassword); err != nil {
			log.Fatalf("ensure admin: %v", err)
		}
	}

	keys, err := crypto.LoadOrGenerate(ctx, st)
	if err != nil {
		log.Fatalf("load keys: %v", err)
	}

	tmpls, err := parseTemplates()
	if err != nil {
		log.Fatalf("parse templates: %v", err)
	}

	handler := server.New(cfg, st, keys, tmpls, staticHandler())

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("listening on :%s  issuer=%s", port, cfg.Issuer)
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}

var tmplFuncs = template.FuncMap{
	"scopeLabel": func(s string) string {
		switch s {
		case "openid":  return "确认您的身份"
		case "email":   return "读取您的电子邮箱"
		case "profile": return "读取您的公开资料（显示名称、头像、角色）"
		case "role":    return "读取您的角色"
		default:        return s
		}
	},
	// safeHTML marks a string as trusted HTML (used for TOS/Privacy content).
	"safeHTML": func(s string) template.HTML {
		return template.HTML(s) //nolint:gosec
	},
	// urlEncode percent-encodes a string for safe use as a URL query value.
	"urlEncode": url.QueryEscape,
	// providerIconSVG returns a built-in SVG icon for known providers.
	"providerIconSVG": func(slug, icon string) template.HTML {
		key := strings.ToLower(strings.TrimSpace(slug))
		if key == "" {
			key = strings.ToLower(strings.TrimSpace(icon))
		}
		switch key {
		case "google":
			return template.HTML(`<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#EA4335" d="M12 10.2v3.9h5.5c-.3 1.5-1.8 4.3-5.5 4.3-3.3 0-6-2.7-6-6.1s2.7-6.1 6-6.1c1.9 0 3.2.8 3.9 1.5l2.7-2.6C17 3.6 14.8 2.6 12 2.6a9.4 9.4 0 0 0 0 18.8c5.4 0 9-3.8 9-9.1 0-.6-.1-1.2-.2-2H12z"/><path fill="#4285F4" d="M3.5 7.6l3.2 2.3A6 6 0 0 1 12 6.2c1.9 0 3.2.8 3.9 1.5l2.7-2.6C17 3.6 14.8 2.6 12 2.6a9.4 9.4 0 0 0-8.5 5z"/><path fill="#FBBC05" d="M12 21.4c2.7 0 4.9-.9 6.5-2.5l-3-2.4c-.8.6-2 1-3.5 1-3.6 0-5.2-2.7-5.5-4.2l-3.2 2.4a9.4 9.4 0 0 0 8.7 5.7z"/><path fill="#34A853" d="M3.3 15.7l3.2-2.4c-.2-.6-.4-1.1-.4-1.8s.1-1.2.4-1.8L3.3 7.3A9.4 9.4 0 0 0 2.6 12c0 1.4.3 2.7.7 3.7z"/></svg>`) //nolint:gosec
		case "x", "x.com", "xcom", "twitter":
			return template.HTML(`<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="1" y="1" width="22" height="22" rx="5" fill="#111827"/><path d="M7 6.5h2.8l3.1 4.3 3.6-4.3h2.7l-5.2 6.1 5.5 7h-2.8l-3.5-4.6-4 4.6H6.5l5.7-6.6L7 6.5zm3.2 1.7H9l6 9.7h1.2l-6-9.7z" fill="#fff"/></svg>`) //nolint:gosec
		default:
			return ""
		}
	},
}

func parseTemplates() (map[string]*template.Template, error) {
	sub, err := fs.Sub(templateFS, "web/templates")
	if err != nil {
		return nil, err
	}

	names := []string{
		"home", "login", "login_2fa", "register", "consent", "profile", "error",
		"tos", "privacy", "verify_email", "forgot_password", "reset_password",
		"force_change_password", "oidc_first_login",
		"admin_dashboard", "admin_users", "admin_user_detail",
		"admin_clients", "admin_client_create", "admin_client_created", "admin_client_detail", "admin_client_secret",
		"admin_providers", "admin_provider_detail", "admin_roles", "admin_announcements", "admin_settings",
		"admin_groups", "admin_group_detail",
		"member_projects", "member_project_edit",
		"member_links", "member_link_edit",
	}

	out := make(map[string]*template.Template, len(names))
	for _, name := range names {
		t, err := template.New(name).Funcs(tmplFuncs).ParseFS(sub, "base.html", name+".html")
		if err != nil {
			return nil, err
		}
		out[name] = t
	}
	return out, nil
}

func staticHandler() http.Handler {
	sub, _ := fs.Sub(staticFS, "web/static")
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}
