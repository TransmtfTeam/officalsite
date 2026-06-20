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
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"transmtf.com/oidc/internal/config"
	"transmtf.com/oidc/internal/crypto"
	"transmtf.com/oidc/internal/store"
)

type ctxKey int

const (
	ctxUser ctxKey = iota
	ctxCSRF
)

type Handler struct {
	cfg     *config.Config
	st      *store.Store
	keys    *crypto.Keys
	tmpls   map[string]*template.Template
	appDist fs.FS
}

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
	if formTok == "" {
		// SPA mutations submit the token via header (the cookie is HttpOnly).
		formTok = r.Header.Get("X-CSRF-Token")
	}
	return h.verifyCSRFValue(cookieTok, formTok)
}

func (h *Handler) verifyCSRFValue(cookieTok, formTok string) bool {
	if !isValidCSRFToken(cookieTok) || !isValidCSRFToken(formTok) {
		return false
	}
	return hmac.Equal([]byte(cookieTok), []byte(formTok))
}

func (h *Handler) csrfFailed(w http.ResponseWriter, r *http.Request) {
	h.renderError(w, r, http.StatusForbidden, "请求已拒绝", "安全校验失败，请刷新页面后重试")
}

// currentUser returns the logged-in user or nil.
func (h *Handler) currentUser(r *http.Request) *store.User {
	if u, ok := r.Context().Value(ctxUser).(*store.User); ok {
		return u
	}
	return nil
}

func (h *Handler) isSystemAdminUser(u *store.User) bool {
	if u == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(u.Email), strings.TrimSpace(h.cfg.AdminEmail))
}

func (h *Handler) sessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if shouldEnsureCSRFCookie(r) {
			csrfTok := h.ensureCSRFCookie(w, r)
			r = r.WithContext(context.WithValue(r.Context(), ctxCSRF, csrfTok))
		}
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
		u := h.currentUser(r)
		if u == nil {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		if mustChangePasswordNow(u, r.URL.Path) {
			http.Redirect(w, r, "/profile/change-password?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		next(w, r)
	}
}

func (h *Handler) requireMember(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := h.currentUser(r)
		if u == nil {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		if mustChangePasswordNow(u, r.URL.Path) {
			http.Redirect(w, r, "/profile/change-password?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		if !u.IsMember() {
			h.renderError(w, r, http.StatusForbidden, "访问被拒绝", "需要成员或管理员权限")
			return
		}
		next(w, r)
	}
}

func (h *Handler) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := h.currentUser(r)
		if u == nil {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		if mustChangePasswordNow(u, r.URL.Path) {
			http.Redirect(w, r, "/profile/change-password?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		if !u.IsAdmin() {
			h.renderError(w, r, http.StatusForbidden, "访问被拒绝", "需要管理员权限")
			return
		}
		next(w, r)
	}
}

// requirePermission allows access if the user is admin OR has the given permission
// via their custom role. The built-in "member" role implies manage_projects,
// manage_clients, and manage_announcements.
func (h *Handler) requirePermission(perm string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			u := h.currentUser(r)
			if u == nil {
				http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
				return
			}
			if mustChangePasswordNow(u, r.URL.Path) {
				http.Redirect(w, r, "/profile/change-password?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
				return
			}
			if !h.userHasPermission(r.Context(), u, perm) {
				h.renderError(w, r, http.StatusForbidden, "访问被拒绝", "权限不足")
				return
			}
			next(w, r)
		}
	}
}

func mustChangePasswordNow(u *store.User, path string) bool {
	if u == nil || !u.RequirePasswordChange {
		return false
	}
	switch path {
	case "/profile/change-password", "/logout", "/profile/passkey/register/begin", "/profile/passkey/register/finish":
		return false
	default:
		return true
	}
}

// userHasPermission returns true if the user is admin, a member with an implied
// permission, or has a custom role that explicitly includes the permission.
func (h *Handler) userHasPermission(ctx context.Context, u *store.User, perm string) bool {
	if u.IsAdmin() {
		return true
	}
	// Member role implies these permissions.
	memberImplied := map[string]bool{
		"manage_projects":      true,
		"manage_clients":       true,
		"manage_announcements": true,
		"manage_groups":        true,
		"view_users":           true,
		"moderate_users":       true, // verify-email and toggle-status for member users
	}
	if u.IsMember() && memberImplied[perm] {
		return true
	}
	// Custom role: check explicitly assigned permissions.
	if !store.IsDefaultRole(u.Role) {
		role, err := h.st.GetCustomRole(ctx, u.Role)
		if err == nil && role != nil {
			for _, p := range role.Permissions {
				if p == perm {
					return true
				}
			}
		}
	}
	return false
}

type PageData struct {
	Title       string
	CurrentUser *store.User
	Flash       string
	IsError     bool
	CSRFToken   string
	// site config (loaded for every page)
	SiteName     string
	SiteIconURL  string
	Issuer       string
	ContactEmail string
	AnnZH        string
	AnnEN        string
	AnnHash      string
	// page-specific
	Data any
}

func (h *Handler) pageData(r *http.Request, title string) PageData {
	ctx := r.Context()
	cfg := h.st.GetAllSettings(ctx)
	name := cfg["site_name"]
	if name == "" {
		name = "团队站点"
	}
	csrf := h.csrfTokenFromRequest(r)
	if !isValidCSRFToken(csrf) {
		if tok, ok := r.Context().Value(ctxCSRF).(string); ok {
			csrf = tok
		}
	}
	return PageData{
		Title:        title,
		CurrentUser:  h.currentUser(r),
		CSRFToken:    csrf,
		SiteName:     name,
		SiteIconURL:  cfg["site_icon_url"],
		Issuer:       h.cfg.Issuer,
		ContactEmail: orDefault(cfg["contact_email"], "contact@transmtf.com"),
		AnnZH:        cfg["ann_zh"],
		AnnEN:        cfg["ann_en"],
		AnnHash:      shortHash(cfg["ann_zh"] + "|" + cfg["ann_en"]),
	}
}

func (h *Handler) render(w http.ResponseWriter, name string, d PageData) {
	tmpl, ok := h.tmpls[name]
	if !ok {
		http.Error(w, "模板不存在："+name, 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "base", d); err != nil {
		log.Printf("template %s error: %v", name, err)
	}
}

func (h *Handler) renderError(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	w.WriteHeader(status)
	d := h.pageData(r, "错误")
	d.Flash = fmt.Sprintf("%s - %s", title, detail)
	d.IsError = true
	h.render(w, "error", d)
}

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

func New(cfg *config.Config, st *store.Store, keys *crypto.Keys, tmpls map[string]*template.Template, static http.Handler, appDist fs.FS) http.Handler {
	h := &Handler{cfg: cfg, st: st, keys: keys, tmpls: tmpls, appDist: appDist}

	// Background audit-log cleanup (90 day retention).
	h.startAuditCleanup()

	mux := http.NewServeMux()

	// Static files (caller supplies embedded or filesystem handler)
	mux.Handle("GET /static/", static)
	// Uploaded project images
	mux.Handle("GET /uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("uploads"))))

	// ── React SPA assets + JSON API base ──
	// Hashed, immutable Vite build assets.
	mux.Handle("GET /app/assets/", h.spaAssetsHandler())
	// SPA bootstrap: current user, CSRF token, settings, capabilities.
	mux.HandleFunc("GET /api/v1/me", h.APIMe)
	// JSON API surface consumed by the React SPA.
	registerAuthAPIRoutes(mux, h)
	registerProfileAPIRoutes(mux, h)
	registerMemberAPIRoutes(mux, h)
	registerAdminUsersAPIRoutes(mux, h)
	registerAdminClientsAPIRoutes(mux, h)
	registerAdminMiscAPIRoutes(mux, h)
	registerOAuthAPIRoutes(mux, h)
	// JSON 404 for any unknown /api/v1 path (scoped so legacy /api/* endpoints win).
	mux.Handle("/api/v1/", http.HandlerFunc(apiNotFound))

	// favicon (served from site settings)
	mux.HandleFunc("GET /favicon.png", h.SiteFaviconFile)
	mux.HandleFunc("GET /favicon.jpg", h.SiteFaviconFile)
	mux.HandleFunc("GET /favicon.ico", h.AdminSiteIcon)

	// OIDC RP - external provider login (browser navigations; the callback sets the
	// session cookie and 302s into the SPA). first-login is a React route that reads
	// /api/v1/login/oidc-challenge, so no server-rendered first-login route is needed.
	mux.HandleFunc("GET /auth/oidc/{slug}", h.OIDCProviderLogin)
	mux.HandleFunc("GET /auth/oidc/{slug}/callback", h.OIDCProviderCallback)

	// OIDC discovery
	mux.HandleFunc("GET /.well-known/openid-configuration", h.Discovery)
	mux.HandleFunc("GET /.well-known/jwks.json", h.JWKS)

	// OIDC protocol (this server as provider). GET /oauth2/authorize falls through to
	// the SPA shell; consent runs in React via the /api/v1/oauth2/authorize endpoints.
	mux.HandleFunc("POST /oauth2/token", h.Token)
	mux.HandleFunc("GET /oauth2/userinfo", h.UserInfo)
	mux.HandleFunc("POST /oauth2/userinfo", h.UserInfo)
	mux.HandleFunc("POST /oauth2/revoke", h.Revoke)
	mux.HandleFunc("POST /oauth2/introspect", h.Introspect)

	// SPA-consumed endpoints kept at their original paths (binary QR + WebAuthn).
	mux.HandleFunc("GET /profile/2fa/qr", h.requireLogin(h.Profile2FAQR))
	mux.HandleFunc("GET /profile/passkey/register/begin", h.requireLogin(h.PasskeyRegisterBegin))
	mux.HandleFunc("POST /profile/passkey/register/finish", h.requireLogin(h.PasskeyRegisterFinish))
	// Passkey login (2FA step) - under /login/2fa/ so the 2FA challenge cookie (path=/login/2fa) is included
	mux.HandleFunc("GET /login/2fa/passkey/begin", h.PasskeyLoginBegin)
	mux.HandleFunc("POST /login/2fa/passkey/finish", h.PasskeyLoginFinish)
	// Passkey primary login (no auth required, unauthenticated)
	mux.HandleFunc("GET /login/passkey/begin", h.PasskeyPrimaryLoginBegin)
	mux.HandleFunc("POST /login/passkey/finish", h.PasskeyPrimaryLoginFinish)

	// All admin / member / profile / auth pages and their mutations are served by the
	// React SPA (human routes -> SPA shell below; data/mutations -> /api/v1/...).

	// Public API (legacy /api/* endpoints; not under /api/v1)
	mux.HandleFunc("GET /api/announcement/{clientid}", h.AnnouncementAPI)
	mux.HandleFunc("GET /api/site-icon", h.AdminSiteIcon)
	mux.HandleFunc("GET /manifest.json", h.PWAManifest)

	// SPA shell: every human-facing GET not matched by a more specific pattern
	// (API / protocol / assets / uploads / well-known) renders index.html and lets
	// React route client-side. The emailed /verify-email?token= link lands here and
	// the React page posts the token to /api/v1/verify-email.
	mux.HandleFunc("GET /", h.serveSPAShell)

	// Wrap with security middlewares.
	return h.securityHeadersMiddleware(h.sessionMiddleware(mux))
}

func isErrNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// shortHash returns a short hex digest of s, used as a dismissal key for
// the announcement modal so users only need to dismiss it once per revision.
func shortHash(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
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

// Only issue/refresh CSRF cookies for top-level HTML document GET requests.
// This avoids concurrent subresource responses racing to overwrite the CSRF cookie.
func shouldEnsureCSRFCookie(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if strings.HasPrefix(r.URL.Path, "/static/") {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func safeNextPath(next, fallback string) string {
	next = strings.TrimSpace(next)
	if next == "" {
		return fallback
	}
	// Must be a server-relative path to prevent open redirects.
	// Reject protocol-relative (//) and anything with backslash or newlines.
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") ||
		strings.ContainsAny(next, "\r\n\\") {
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

// PWAManifest returns a minimal Web App Manifest using the site settings.
func (h *Handler) PWAManifest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	siteName := orDefault(h.st.GetSetting(ctx, "site_name"), "团队站点")
	iconURL := h.st.GetSetting(ctx, "site_icon_url")

	type iconEntry struct {
		Src   string `json:"src"`
		Sizes string `json:"sizes"`
		Type  string `json:"type"`
	}
	type manifest struct {
		Name            string      `json:"name"`
		ShortName       string      `json:"short_name"`
		StartURL        string      `json:"start_url"`
		Display         string      `json:"display"`
		BackgroundColor string      `json:"background_color"`
		ThemeColor      string      `json:"theme_color"`
		Icons           []iconEntry `json:"icons,omitempty"`
		Lang            string      `json:"lang"`
	}

	m := manifest{
		Name:            siteName,
		ShortName:       siteName,
		StartURL:        "/",
		Display:         "standalone",
		BackgroundColor: "#f8fafc",
		ThemeColor:      "#55CDFC",
		Lang:            "zh-CN",
	}

	if iconURL != "" {
		// Detect MIME type from the icon URL.
		mime := "image/png"
		lower := strings.ToLower(iconURL)
		if strings.HasPrefix(lower, "data:") {
			// data:image/png;base64,... -> extract the MIME type.
			rest := strings.TrimPrefix(lower, "data:")
			if semi := strings.IndexByte(rest, ';'); semi > 0 {
				mime = rest[:semi]
			}
		} else if strings.HasSuffix(lower, ".svg") {
			mime = "image/svg+xml"
		} else if strings.HasSuffix(lower, ".jpg") || strings.HasSuffix(lower, ".jpeg") {
			mime = "image/jpeg"
		} else if strings.HasSuffix(lower, ".webp") {
			mime = "image/webp"
		}
		m.Icons = []iconEntry{{Src: "/api/site-icon", Sizes: "512x512", Type: mime}}
	}

	w.Header().Set("Content-Type", "application/manifest+json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(m)
}
