package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"transmtf.com/oidc/internal/store"
)

// knownPermissions enumerates every permission string the app gates on, so the
// SPA can be told the current user's effective capability set in one round trip.
var knownPermissions = []string{
	"manage_users", "manage_clients", "manage_projects", "view_users",
	"moderate_users", "manage_providers", "manage_roles",
	"manage_announcements", "manage_settings", "manage_groups",
}

// ── JSON envelope ──────────────────────────────────────────────────────────

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type apiEnvelope struct {
	OK          bool              `json:"ok"`
	Data        any               `json:"data,omitempty"`
	Error       *apiError         `json:"error,omitempty"`
	FieldErrors map[string]string `json:"fieldErrors,omitempty"`
	Flash       string            `json:"flash,omitempty"`
}

func apiOK(w http.ResponseWriter, status int, data any) {
	jsonResp(w, status, apiEnvelope{OK: true, Data: data})
}

func apiOKFlash(w http.ResponseWriter, status int, data any, flash string) {
	jsonResp(w, status, apiEnvelope{OK: true, Data: data, Flash: flash})
}

func apiErr(w http.ResponseWriter, status int, code, message string) {
	jsonResp(w, status, apiEnvelope{OK: false, Error: &apiError{Code: code, Message: message}})
}

func apiFieldErr(w http.ResponseWriter, fields map[string]string, message string) {
	jsonResp(w, http.StatusUnprocessableEntity, apiEnvelope{
		OK:          false,
		Error:       &apiError{Code: "validation", Message: message},
		FieldErrors: fields,
	})
}

func apiCSRFFailed(w http.ResponseWriter) {
	apiErr(w, http.StatusForbidden, "csrf_failed", "安全校验失败，请刷新页面后重试")
}

func apiNotFound(w http.ResponseWriter, r *http.Request) {
	apiErr(w, http.StatusNotFound, "not_found", "接口不存在")
}

// decodeJSON reads a JSON request body into dst with a sane size limit. Returns
// false (after writing a 400) when the body is unparseable.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil && err != io.EOF {
		apiErr(w, http.StatusBadRequest, "bad_request", "请求格式错误")
		return false
	}
	return true
}

// ── CSRF for JSON mutations ────────────────────────────────────────────────

// verifyAPICSRF validates the double-submit token for an API mutation. The token
// may arrive either in the X-CSRF-Token header (preferred for fetch) or, for
// multipart submissions, as a csrf_token form field. verifyCSRFToken already
// checks both since it falls back to the header.
func (h *Handler) verifyAPICSRF(r *http.Request) bool {
	return h.verifyCSRFToken(r)
}

// ── JSON auth guards (never redirect) ──────────────────────────────────────

// apiMustChangePassword mirrors mustChangePasswordNow but whitelists the API
// paths a user must still be able to reach while a password change is pending.
func apiMustChangePassword(u *store.User, path string) bool {
	if u == nil || !u.RequirePasswordChange {
		return false
	}
	switch path {
	case "/api/v1/profile/change-password", "/api/v1/logout", "/api/v1/me":
		return false
	}
	return true
}

func (h *Handler) apiGuard(u *store.User, w http.ResponseWriter, r *http.Request) bool {
	if u == nil {
		apiErr(w, http.StatusUnauthorized, "unauthorized", "请先登录")
		return false
	}
	if apiMustChangePassword(u, r.URL.Path) {
		apiErr(w, http.StatusForbidden, "password_change_required", "请先修改密码")
		return false
	}
	return true
}

func (h *Handler) apiRequireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := h.currentUser(r)
		if !h.apiGuard(u, w, r) {
			return
		}
		next(w, r)
	}
}

func (h *Handler) apiRequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := h.currentUser(r)
		if !h.apiGuard(u, w, r) {
			return
		}
		if !u.IsAdmin() {
			apiErr(w, http.StatusForbidden, "forbidden", "需要管理员权限")
			return
		}
		next(w, r)
	}
}

func (h *Handler) apiRequirePermission(perm string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			u := h.currentUser(r)
			if !h.apiGuard(u, w, r) {
				return
			}
			if !h.userHasPermission(r.Context(), u, perm) {
				apiErr(w, http.StatusForbidden, "forbidden", "权限不足")
				return
			}
			next(w, r)
		}
	}
}

// requireAPICSRF wraps a mutating handler with CSRF verification.
func (h *Handler) requireAPICSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.verifyAPICSRF(r) {
			apiCSRFFailed(w)
			return
		}
		next(w, r)
	}
}

// ── DTOs ───────────────────────────────────────────────────────────────────

type userDTO struct {
	ID                    string `json:"id"`
	Email                 string `json:"email"`
	DisplayName           string `json:"displayName"`
	AvatarURL             string `json:"avatarUrl"`
	Role                  string `json:"role"`
	Active                bool   `json:"active"`
	EmailVerified         bool   `json:"emailVerified"`
	TOTPEnabled           bool   `json:"totpEnabled"`
	RequirePasswordChange bool   `json:"requirePasswordChange"`
	CreatedAt             string `json:"createdAt"`
}

func toUserDTO(u *store.User) *userDTO {
	if u == nil {
		return nil
	}
	return &userDTO{
		ID:                    u.ID,
		Email:                 u.Email,
		DisplayName:           u.DisplayName,
		AvatarURL:             u.AvatarURL,
		Role:                  u.Role,
		Active:                u.Active,
		EmailVerified:         u.EmailVerified,
		TOTPEnabled:           u.TOTPEnabled,
		RequirePasswordChange: u.RequirePasswordChange,
		CreatedAt:             u.CreatedAt.Format(time.RFC3339),
	}
}

func toUserDTOs(us []*store.User) []*userDTO {
	out := make([]*userDTO, 0, len(us))
	for _, u := range us {
		out = append(out, toUserDTO(u))
	}
	return out
}

// ── Bootstrap endpoint ──────────────────────────────────────────────────────

// APIMe returns the current auth state, a fresh CSRF token, site settings and
// the user's effective capabilities. It is intentionally NOT login-guarded so
// the SPA can hydrate (and obtain a CSRF token) while logged out.
func (h *Handler) APIMe(w http.ResponseWriter, r *http.Request) {
	csrf := h.ensureCSRFCookie(w, r)
	u := h.currentUser(r)
	ctx := r.Context()
	cfg := h.st.GetAllSettings(ctx)
	siteName := cfg["site_name"]
	if siteName == "" {
		siteName = "团队站点"
	}
	resp := map[string]any{
		"user":                  toUserDTO(u),
		"csrfToken":             csrf,
		"requirePasswordChange": u != nil && u.RequirePasswordChange,
		"settings": map[string]any{
			"siteName":     siteName,
			"siteIconUrl":  cfg["site_icon_url"],
			"issuer":       h.cfg.Issuer,
			"contactEmail": orDefault(cfg["contact_email"], "contact@transmtf.com"),
			"annZH":        cfg["ann_zh"],
			"annEN":        cfg["ann_en"],
			"annHash":      shortHash(cfg["ann_zh"] + "|" + cfg["ann_en"]),
		},
		"capabilities": h.userCapabilities(ctx, u),
	}
	apiOK(w, http.StatusOK, resp)
}

func (h *Handler) userCapabilities(ctx context.Context, u *store.User) map[string]any {
	caps := map[string]any{
		"isAdmin":       false,
		"isMember":      false,
		"isSystemAdmin": false,
		"permissions":   []string{},
	}
	if u == nil {
		return caps
	}
	caps["isAdmin"] = u.IsAdmin()
	caps["isMember"] = u.IsMember()
	caps["isSystemAdmin"] = h.isSystemAdminUser(u)
	perms := make([]string, 0, len(knownPermissions))
	for _, p := range knownPermissions {
		if h.userHasPermission(ctx, u, p) {
			perms = append(perms, p)
		}
	}
	caps["permissions"] = perms
	return caps
}

// formValue is a small helper that trims a form field.
func formValue(r *http.Request, key string) string {
	return strings.TrimSpace(r.FormValue(key))
}
