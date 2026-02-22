package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"transmtf.com/oidc/internal/config"
	"transmtf.com/oidc/internal/crypto"
	"transmtf.com/oidc/internal/store"
)

// ── Context keys ─────────────────────────────────────────────────

type ctxKey int

const (
	ctxUser ctxKey = iota
	ctxCSRF
)

// ── Handler ──────────────────────────────────────────────────────

type Handler struct {
	cfg    *config.Config
	st     *store.Store
	keys   *crypto.Keys
	tmpls  map[string]*template.Template
}

// ── Session cookie ────────────────────────────────────────────────

const cookieName = "tmtf_session"
const csrfCookieName = "tmtf_csrf"
const twoFACookieName = "tmtf_2fa"

func (h *Handler) setSessionCookie(w http.ResponseWriter, sessionID string) {
	sig := h.signCookie("session", sessionID)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    sessionID + "." + sig,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.secureCookies(),
		MaxAge:   int(7 * 24 * time.Hour / time.Second),
	})
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.secureCookies(),
		MaxAge:   -1,
	})
}

func (h *Handler) signCookie(scope, id string) string {
	mac := hmac.New(sha256.New, []byte(h.cfg.SessionSecret))
	mac.Write([]byte(scope))
	mac.Write([]byte{':'})
	mac.Write([]byte(id))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (h *Handler) sessionFromRequest(r *http.Request) string {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 {
		return ""
	}
	id, sig := parts[0], parts[1]
	if !hmac.Equal([]byte(sig), []byte(h.signCookie("session", id))) {
		return ""
	}
	return id
}

func (h *Handler) set2FAChallengeCookie(w http.ResponseWriter, challengeID string) {
	sig := h.signCookie("2fa", challengeID)
	http.SetCookie(w, &http.Cookie{
		Name:     twoFACookieName,
		Value:    challengeID + "." + sig,
		Path:     "/login/2fa",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.secureCookies(),
		MaxAge:   int(15 * time.Minute / time.Second),
	})
}

func (h *Handler) clear2FAChallengeCookie(w http.ResponseWriter) {
	expire := func(path string) {
		http.SetCookie(w, &http.Cookie{
			Name:     twoFACookieName,
			Value:    "",
			Path:     path,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   h.secureCookies(),
			MaxAge:   -1,
		})
	}
	// Clear current narrow cookie and legacy wide-path cookie.
	expire("/login/2fa")
	expire("/")
}

func (h *Handler) twoFAChallengeFromRequest(r *http.Request) string {
	c, err := r.Cookie(twoFACookieName)
	if err != nil {
		return ""
	}
	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 {
		return ""
	}
	id, sig := parts[0], parts[1]
	if !hmac.Equal([]byte(sig), []byte(h.signCookie("2fa", id))) {
		return ""
	}
	return id
}

func (h *Handler) setCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.secureCookies(),
		MaxAge:   int(7 * 24 * time.Hour / time.Second),
	})
}

func (h *Handler) csrfTokenFromRequest(r *http.Request) string {
	c, err := r.Cookie(csrfCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func (h *Handler) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) string {
	if tok := h.csrfTokenFromRequest(r); isValidCSRFToken(tok) {
		return tok
	}
	tok := store.RandomHex(32)
	h.setCSRFCookie(w, tok)
	return tok
}

func (h *Handler) verifyCSRFToken(r *http.Request) bool {
	cookieTok := h.csrfTokenFromRequest(r)
	formTok := r.FormValue("csrf_token")
	if !isValidCSRFToken(cookieTok) || !isValidCSRFToken(formTok) {
		return false
	}
	return hmac.Equal([]byte(cookieTok), []byte(formTok))
}

func (h *Handler) csrfFailed(w http.ResponseWriter, r *http.Request) {
	h.renderError(w, r, http.StatusForbidden, "Request Rejected", "CSRF validation failed; please refresh and try again")
}

// currentUser returns the logged-in user or nil.
func (h *Handler) currentUser(r *http.Request) *store.User {
	if u, ok := r.Context().Value(ctxUser).(*store.User); ok {
		return u
	}
	return nil
}

// ── Auth middleware ───────────────────────────────────────────────

func (h *Handler) sessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		csrfTok := h.ensureCSRFCookie(w, r)
		r = r.WithContext(context.WithValue(r.Context(), ctxCSRF, csrfTok))
		sid := h.sessionFromRequest(r)
		if sid != "" {
			if u, err := h.st.GetSessionUser(r.Context(), sid); err == nil {
				r = r.WithContext(context.WithValue(r.Context(), ctxUser, u))
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) requireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.currentUser(r) == nil {
			http.Redirect(w, r, "/login?next="+r.URL.RequestURI(), http.StatusFound)
			return
		}
		next(w, r)
	}
}

func (h *Handler) requireMember(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := h.currentUser(r)
		if u == nil {
			http.Redirect(w, r, "/login?next="+r.URL.RequestURI(), http.StatusFound)
			return
		}
		if !u.IsMember() {
			h.renderError(w, r, http.StatusForbidden, "Forbidden", "member or admin role is required")
			return
		}
		next(w, r)
	}
}

func (h *Handler) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := h.currentUser(r)
		if u == nil {
			http.Redirect(w, r, "/login?next="+r.URL.RequestURI(), http.StatusFound)
			return
		}
		if !u.IsAdmin() {
			h.renderError(w, r, http.StatusForbidden, "Forbidden", "admin role is required")
			return
		}
		next(w, r)
	}
}

// ── Template data ─────────────────────────────────────────────────

type PageData struct {
	Title       string
	CurrentUser *store.User
	Flash       string
	IsError     bool
	CSRFToken   string
	// site config (loaded for every page)
	SiteName     string
	Issuer       string
	ContactEmail string
	AnnZH        string
	AnnEN        string
	// page-specific
	Data any
}

func (h *Handler) pageData(r *http.Request, title string) PageData {
	ctx := r.Context()
	cfg := h.st.GetAllSettings(ctx)
	name := cfg["site_name"]
	if name == "" {
		name = "Team TransMTF"
	}
	csrf := h.csrfTokenFromRequest(r)
	if csrf == "" {
		if tok, ok := r.Context().Value(ctxCSRF).(string); ok {
			csrf = tok
		}
	}
	return PageData{
		Title:        title,
		CurrentUser:  h.currentUser(r),
		CSRFToken:    csrf,
		SiteName:     name,
		Issuer:       h.cfg.Issuer,
		ContactEmail: orDefault(cfg["contact_email"], "contact@transmtf.com"),
		AnnZH:        cfg["ann_zh"],
		AnnEN:        cfg["ann_en"],
	}
}

func (h *Handler) render(w http.ResponseWriter, name string, d PageData) {
	tmpl, ok := h.tmpls[name]
	if !ok {
		http.Error(w, "template not found: "+name, 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "base", d); err != nil {
		log.Printf("template %s error: %v", name, err)
	}
}

func (h *Handler) renderError(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	w.WriteHeader(status)
	d := h.pageData(r, "Error")
	d.Flash = fmt.Sprintf("%s - %s", title, detail)
	d.IsError = true
	h.render(w, "error", d)
}

// ── JSON helpers (for OIDC endpoints) ────────────────────────────

func jsonResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func oidcError(w http.ResponseWriter, status int, code, desc string) {
	jsonResp(w, status, map[string]string{"error": code, "error_description": desc})
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

// ── Routing + server creation ─────────────────────────────────────

func New(cfg *config.Config, st *store.Store, keys *crypto.Keys, tmpls map[string]*template.Template, static http.Handler) http.Handler {
	h := &Handler{cfg: cfg, st: st, keys: keys, tmpls: tmpls}

	mux := http.NewServeMux()

	// Static files (caller supplies embedded or filesystem handler)
	mux.Handle("GET /static/", static)

	// Public pages
	mux.HandleFunc("GET /",          h.Home)
	mux.HandleFunc("GET /login",     h.LoginPage)
	mux.HandleFunc("POST /login",    h.LoginPost)
	mux.HandleFunc("GET /login/2fa", h.Login2FAPage)
	mux.HandleFunc("POST /login/2fa", h.Login2FAPost)
	mux.HandleFunc("GET /logout",    func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/", http.StatusFound) })
	mux.HandleFunc("POST /logout",   h.Logout)
	mux.HandleFunc("GET /register",  h.RegisterPage)
	mux.HandleFunc("POST /register", h.RegisterPost)
	mux.HandleFunc("GET /tos",       h.TOSPage)
	mux.HandleFunc("GET /privacy",   h.PrivacyPage)

	// OIDC RP — external provider login
	mux.HandleFunc("GET /auth/oidc/{slug}",          h.OIDCProviderLogin)
	mux.HandleFunc("GET /auth/oidc/{slug}/callback", h.OIDCProviderCallback)

	// OIDC discovery
	mux.HandleFunc("GET /.well-known/openid-configuration", h.Discovery)
	mux.HandleFunc("GET /.well-known/jwks.json",            h.JWKS)

	// OIDC protocol (this server as provider)
	mux.HandleFunc("GET /oauth2/authorize",   h.requireLogin(h.Authorize))
	mux.HandleFunc("POST /oauth2/authorize",  h.requireLogin(h.AuthorizeConsent))
	mux.HandleFunc("POST /oauth2/token",      h.Token)
	mux.HandleFunc("GET /oauth2/userinfo",    h.UserInfo)
	mux.HandleFunc("POST /oauth2/userinfo",   h.UserInfo)
	mux.HandleFunc("POST /oauth2/revoke",     h.Revoke)
	mux.HandleFunc("POST /oauth2/introspect", h.Introspect)

	// Authenticated user
	mux.HandleFunc("GET /profile",  h.requireLogin(h.Profile))
	mux.HandleFunc("POST /profile", h.requireLogin(h.ProfilePost))
	mux.HandleFunc("POST /profile/2fa/start",  h.requireLogin(h.Profile2FAStart))
	mux.HandleFunc("POST /profile/2fa/enable", h.requireLogin(h.Profile2FAEnable))
	mux.HandleFunc("POST /profile/2fa/disable", h.requireLogin(h.Profile2FADisable))

	// Member panel
	mux.HandleFunc("GET /member/projects",              h.requireMember(h.MemberProjects))
	mux.HandleFunc("POST /member/projects",             h.requireMember(h.MemberProjectCreate))
	mux.HandleFunc("GET /member/projects/{id}/edit",    h.requireMember(h.MemberProjectEdit))
	mux.HandleFunc("POST /member/projects/{id}/edit",   h.requireMember(h.MemberProjectUpdate))
	mux.HandleFunc("POST /member/projects/{id}/delete", h.requireMember(h.MemberProjectDelete))

	// Admin panel
	mux.HandleFunc("GET /admin",                           h.requireAdmin(h.AdminDashboard))
	mux.HandleFunc("GET /admin/users",                     h.requireAdmin(h.AdminUsers))
	mux.HandleFunc("POST /admin/users",                    h.requireAdmin(h.AdminUserCreate))
	mux.HandleFunc("POST /admin/users/{id}/update",        h.requireAdmin(h.AdminUserUpdate))
	mux.HandleFunc("POST /admin/users/{id}/delete",        h.requireAdmin(h.AdminUserDelete))
	mux.HandleFunc("GET /admin/clients",                   h.requireAdmin(h.AdminClients))
	mux.HandleFunc("POST /admin/clients",                  h.requireAdmin(h.AdminClientCreate))
	mux.HandleFunc("POST /admin/clients/{id}/delete",      h.requireAdmin(h.AdminClientDelete))
	mux.HandleFunc("GET /admin/providers",                 h.requireAdmin(h.AdminProviders))
	mux.HandleFunc("POST /admin/providers",                h.requireAdmin(h.AdminProviderCreate))
	mux.HandleFunc("POST /admin/providers/{id}/toggle",    h.requireAdmin(h.AdminProviderToggle))
	mux.HandleFunc("POST /admin/providers/{id}/delete",    h.requireAdmin(h.AdminProviderDelete))
	mux.HandleFunc("GET /admin/settings",                  h.requireAdmin(h.AdminSettings))
	mux.HandleFunc("POST /admin/settings",                 h.requireAdmin(h.AdminSettingsSave))

	// Wrap with security middlewares.
	return h.securityHeadersMiddleware(h.sessionMiddleware(mux))
}

// ── Misc ─────────────────────────────────────────────────────────

func isErrNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func (h *Handler) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"base-uri 'self'; "+
				"object-src 'none'; "+
				"frame-ancestors 'none'; "+
				"form-action 'self'; "+
				"script-src 'self'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' https: data:; "+
				"font-src 'self' data:")
		if h.secureCookies() {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) secureCookies() bool {
	u, err := url.Parse(h.cfg.Issuer)
	return err == nil && strings.EqualFold(u.Scheme, "https")
}

func isValidCSRFToken(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func safeNextPath(next, fallback string) string {
	next = strings.TrimSpace(next)
	if next == "" {
		return fallback
	}
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.Contains(next, `\`) {
		return fallback
	}
	u, err := url.Parse(next)
	if err != nil || u.IsAbs() || u.Host != "" {
		return fallback
	}
	return next
}

func normalizeScopes(scopes []string) []string {
	seen := make(map[string]struct{}, len(scopes))
	var out []string
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func scopesSubset(requested, allowed []string) bool {
	allow := make(map[string]struct{}, len(allowed))
	for _, s := range allowed {
		if s != "" {
			allow[s] = struct{}{}
		}
	}
	for _, s := range requested {
		if _, ok := allow[s]; !ok {
			return false
		}
	}
	return true
}

func isLocalHost(host string) bool {
	h := strings.ToLower(host)
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func isAllowedAbsoluteURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Scheme, "https") {
		return true
	}
	if strings.EqualFold(u.Scheme, "http") && isLocalHost(u.Hostname()) {
		return true
	}
	return false
}
