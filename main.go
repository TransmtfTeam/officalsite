package main

import (
	"context"
	"embed"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"

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
		case "openid":  return "Confirm your identity"
		case "email":   return "Read your email address"
		case "profile": return "Read your public profile (display name, avatar, role)"
		default:        return s
		}
	},
	// safeHTML marks a string as trusted HTML (used for TOS/Privacy content).
	"safeHTML": func(s string) template.HTML {
		return template.HTML(s) //nolint:gosec
	},
}

func parseTemplates() (map[string]*template.Template, error) {
	sub, err := fs.Sub(templateFS, "web/templates")
	if err != nil {
		return nil, err
	}

	names := []string{
		"home", "login", "login_2fa", "register", "consent", "profile", "error",
		"tos", "privacy",
		"admin_dashboard", "admin_users", "admin_user_detail",
		"admin_clients", "admin_client_create", "admin_client_created", "admin_client_detail", "admin_client_secret",
		"admin_providers", "admin_roles", "admin_announcements", "admin_settings",
		"member_projects", "member_project_edit",
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
