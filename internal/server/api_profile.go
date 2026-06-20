package server

import (
	"net/http"
	"strings"
	"time"

	"transmtf.com/oidc/internal/store"
)

// registerProfileAPIRoutes wires the JSON profile API under /api/v1. Every route
// requires an authenticated session (apiRequireLogin); JSON-body mutations also
// require CSRF (requireAPICSRF). The avatar upload is multipart and verifies
// CSRF inside the handler after parsing.
func registerProfileAPIRoutes(mux *http.ServeMux, h *Handler) {
	mux.HandleFunc("GET /api/v1/profile", h.apiRequireLogin(h.APIProfileView))
	// Multipart: do NOT wrap in requireAPICSRF; the handler checks CSRF after parse.
	mux.HandleFunc("POST /api/v1/profile", h.apiRequireLogin(h.APIProfileUpdate))

	mux.HandleFunc("POST /api/v1/profile/delete-password",
		h.apiRequireLogin(h.requireAPICSRF(h.APIProfileDeletePassword)))
	mux.HandleFunc("POST /api/v1/profile/change-password",
		h.apiRequireLogin(h.requireAPICSRF(h.APIProfileForceChange)))
	mux.HandleFunc("POST /api/v1/profile/identities/{slug}/unbind",
		h.apiRequireLogin(h.requireAPICSRF(h.APIProfileIdentityUnbind)))

	mux.HandleFunc("POST /api/v1/profile/2fa/start",
		h.apiRequireLogin(h.requireAPICSRF(h.APIProfile2FAStart)))
	mux.HandleFunc("POST /api/v1/profile/2fa/enable",
		h.apiRequireLogin(h.requireAPICSRF(h.APIProfile2FAEnable)))
	mux.HandleFunc("POST /api/v1/profile/2fa/disable",
		h.apiRequireLogin(h.requireAPICSRF(h.APIProfile2FADisable)))

	mux.HandleFunc("POST /api/v1/profile/passkey/{id}/delete",
		h.apiRequireLogin(h.requireAPICSRF(h.APIPasskeyDelete)))
}

// ── DTOs ─────────────────────────────────────────────────────────────────────

type profilePasskeyDTO struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"createdAt"`
}

type profileProviderDTO struct {
	Slug    string `json:"slug"`
	Name    string `json:"name"`
	Icon    string `json:"icon"`
	Enabled bool   `json:"enabled"`
	Bound   bool   `json:"bound"`
}

func profileToPasskeyDTOs(creds []*store.PasskeyCredential) []profilePasskeyDTO {
	out := make([]profilePasskeyDTO, 0, len(creds))
	for _, c := range creds {
		out = append(out, profilePasskeyDTO{
			ID:        c.ID,
			Name:      c.Name,
			CreatedAt: c.CreatedAt.Format(time.RFC3339),
		})
	}
	return out
}

// profileViewPayload serialises buildProfileViewData into a JSON-safe map. It
// reuses the existing buildProfileViewData (which returns template-shaped data)
// and re-projects its fields into camelCase DTOs without leaking secrets.
func (h *Handler) profileViewPayload(r *http.Request, u *store.User) map[string]any {
	data := h.buildProfileViewData(r.Context(), u)

	passkeys, _ := data["Passkeys"].([]*store.PasskeyCredential)

	providers := make([]profileProviderDTO, 0)
	if items, ok := data["ExternalProviders"].([]map[string]any); ok {
		for _, it := range items {
			providers = append(providers, profileProviderDTO{
				Slug:    asString(it["Slug"]),
				Name:    asString(it["Name"]),
				Icon:    asString(it["Icon"]),
				Enabled: asBool(it["Enabled"]),
				Bound:   asBool(it["Bound"]),
			})
		}
	}

	payload := map[string]any{
		"user":              toUserDTO(u),
		"hasPassword":       asBool(data["HasPassword"]),
		"passkeys":          profileToPasskeyDTOs(passkeys),
		"passkeyCount":      data["PasskeyCount"],
		"externalProviders": providers,
		"totpEnabled":       u != nil && u.TOTPEnabled,
	}
	// Mid-setup pending 2FA secret/URI, if any.
	if s := asString(data["PendingSecret"]); s != "" {
		payload["pendingSecret"] = s
		payload["pendingUri"] = asString(data["PendingURI"])
	}
	return payload
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}

// ── GET /api/v1/profile ──────────────────────────────────────────────────────

// APIProfileView mirrors Profile (handlers_public.go): returns the account
// overview view data as JSON.
func (h *Handler) APIProfileView(w http.ResponseWriter, r *http.Request) {
	u := h.currentUser(r)
	apiOK(w, http.StatusOK, h.profileViewPayload(r, u))
}

// ── POST /api/v1/profile (multipart) ─────────────────────────────────────────

// APIProfileUpdate mirrors ProfilePost (handlers_public.go): updates display
// name, avatar (avatar_file / clear_avatar) and optional password change.
func (h *Handler) APIProfileUpdate(w http.ResponseWriter, r *http.Request) {
	// Always parse multipart so we accept both regular form fields and the
	// avatar_file upload. Cap body to PublicAvatarOpts.MaxBytes + a small
	// buffer for other form fields.
	r.Body = http.MaxBytesReader(w, r.Body, PublicAvatarOpts.MaxBytes+64*1024)
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(PublicAvatarOpts.MaxBytes + 64*1024); err != nil {
			apiErr(w, http.StatusRequestEntityTooLarge, "too_large", "上传过大或格式错误")
			return
		}
	} else if err := r.ParseForm(); err != nil {
		apiErr(w, http.StatusBadRequest, "bad_request", "请求参数错误")
		return
	}
	if !h.verifyAPICSRF(r) {
		apiCSRFFailed(w)
		return
	}

	u := h.currentUser(r)
	ctx := r.Context()
	name := strings.TrimSpace(r.FormValue("display_name"))
	clearAvatar := r.FormValue("clear_avatar") == "1"
	newPass := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")
	currentPass := r.FormValue("current_password")

	fail := func(msg string) {
		apiErr(w, http.StatusBadRequest, "validation", msg)
	}

	if name == "" {
		fail("显示名称不能为空")
		return
	}
	// Validate password fields BEFORE any writes to avoid partial updates.
	if newPass != "" {
		if store.HasPassword(u) && !h.st.VerifyPassword(u, currentPass) {
			fail("当前密码不正确")
			return
		}
		if len(newPass) < 8 {
			fail("密码至少需要8位")
			return
		}
		if newPass != confirm {
			fail("两次输入的密码不一致")
			return
		}
	}

	// Optional avatar upload (only when actually present).
	var avatarLocalURL string
	if r.MultipartForm != nil {
		if files := r.MultipartForm.File["avatar_file"]; len(files) > 0 && files[0].Size > 0 {
			file, err := files[0].Open()
			if err != nil {
				fail("读取头像失败")
				return
			}
			localURL, uerr := saveUploadedImage(file, "avatars", u.ID, PublicAvatarOpts)
			file.Close()
			if uerr != nil {
				fail(uerr.Error())
				return
			}
			avatarLocalURL = localURL
		}
	}

	if err := h.st.UpdateUser(ctx, u.ID, name, u.Role, u.Active); err != nil {
		fail("保存失败：" + err.Error())
		return
	}
	if avatarLocalURL != "" {
		_ = h.st.UpdateUserAvatar(ctx, u.ID, avatarLocalURL)
	} else if clearAvatar {
		removeUploadByBaseName("avatars", u.ID)
		_ = h.st.UpdateUserAvatar(ctx, u.ID, "")
	}
	if newPass != "" {
		if err := h.st.UpdatePassword(ctx, u.ID, newPass); err != nil {
			fail("密码更新失败")
			return
		}
	}

	// Re-read so the response reflects the saved state.
	saved, err := h.st.GetUserByID(ctx, u.ID)
	if err != nil {
		saved = u
	}
	apiOKFlash(w, http.StatusOK, h.profileViewPayload(r, saved), "已保存")
}

// ── POST /api/v1/profile/delete-password ─────────────────────────────────────

// APIProfileDeletePassword mirrors ProfileDeletePassword (handlers_public.go):
// removes the user's password for passkey-only mode.
func (h *Handler) APIProfileDeletePassword(w http.ResponseWriter, r *http.Request) {
	u := h.currentUser(r)
	ctx := r.Context()
	if h.st.CountPasskeysByUserID(ctx, u.ID) == 0 {
		apiErr(w, http.StatusBadRequest, "validation", "请先添加通行密钥")
		return
	}
	if err := h.st.ClearPassword(ctx, u.ID); err != nil {
		apiErr(w, http.StatusBadRequest, "validation", "删除密码失败")
		return
	}
	apiOKFlash(w, http.StatusOK, h.profileViewPayload(r, u), "密码已删除")
}

// ── POST /api/v1/profile/change-password ─────────────────────────────────────

// APIProfileForceChange mirrors ProfileForceChangePost (handlers_public.go):
// handles the forced password change. On success returns {redirect} pointing at
// the path the form handler would have redirected to.
func (h *Handler) APIProfileForceChange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
		Next            string `json:"next"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	u := h.currentUser(r)
	newPass := req.NewPassword
	confirm := req.ConfirmPassword
	next := safeNextPath(req.Next, "")

	// Only allow this handler when the flag is actually set.
	if !u.RequirePasswordChange {
		target := next
		if target == "" {
			target = "/profile"
		}
		apiOK(w, http.StatusOK, map[string]any{"redirect": target})
		return
	}

	if len(newPass) < 8 {
		apiErr(w, http.StatusBadRequest, "validation", "新密码至少 8 位。")
		return
	}
	if newPass != confirm {
		apiErr(w, http.StatusBadRequest, "validation", "两次输入的密码不一致。")
		return
	}
	if err := h.st.UpdatePasswordAndClearFlag(r.Context(), u.ID, newPass); err != nil {
		apiErr(w, http.StatusBadRequest, "validation", "密码更新失败："+err.Error())
		return
	}
	target := safeNextPath(next, "/profile")
	if target == "/profile" {
		target = "/profile?flash=密码已更新"
	}
	apiOK(w, http.StatusOK, map[string]any{"redirect": target})
}

// ── POST /api/v1/profile/identities/{slug}/unbind ────────────────────────────

// APIProfileIdentityUnbind mirrors ProfileIdentityUnbind (handlers_public.go):
// unbinds an external identity provider from the current user.
func (h *Handler) APIProfileIdentityUnbind(w http.ResponseWriter, r *http.Request) {
	u := h.currentUser(r)
	slug := r.PathValue("slug")
	ctx := r.Context()
	if _, err := h.st.GetUserIdentityByUserAndProvider(ctx, u.ID, slug); err != nil {
		if isErrNoRows(err) {
			apiErr(w, http.StatusBadRequest, "validation", "该登录方式尚未绑定")
			return
		}
		apiErr(w, http.StatusBadRequest, "validation", "读取绑定状态失败")
		return
	}
	affected, err := h.st.DeleteUserIdentityByUserAndProvider(ctx, u.ID, slug)
	if err != nil {
		apiErr(w, http.StatusBadRequest, "validation", "解绑失败")
		return
	}
	if affected == 0 {
		apiErr(w, http.StatusBadRequest, "validation", "该登录方式尚未绑定")
		return
	}
	apiOKFlash(w, http.StatusOK, h.profileViewPayload(r, u), "登录方式解绑成功")
}

// ── POST /api/v1/profile/2fa/start ───────────────────────────────────────────

// APIProfile2FAStart mirrors Profile2FAStart (handlers_2fa.go): generates and
// persists a pending TOTP secret, then returns it along with the provisioning
// (otpauth) URI.
func (h *Handler) APIProfile2FAStart(w http.ResponseWriter, r *http.Request) {
	u := h.currentUser(r)
	if u.TOTPEnabled {
		apiErr(w, http.StatusBadRequest, "validation", "双重验证已启用")
		return
	}

	secret, err := newTOTPSecret()
	if err != nil {
		apiErr(w, http.StatusBadRequest, "validation", "无法生成动态口令密钥")
		return
	}
	if err := h.st.SavePendingTOTPSecret(r.Context(), u.ID, secret); err != nil {
		apiErr(w, http.StatusBadRequest, "validation", "保存双重验证配置失败")
		return
	}
	siteName := orDefault(h.st.GetSetting(r.Context(), "site_name"), "团队站点")
	uri := buildTOTPUri(siteName, u.Email, secret)
	apiOKFlash(w, http.StatusOK, map[string]any{
		"secret":     secret,
		"otpauthUri": uri,
	}, "已生成动态口令密钥，请继续完成启用")
}

// ── POST /api/v1/profile/2fa/enable ──────────────────────────────────────────

// APIProfile2FAEnable mirrors Profile2FAEnable (handlers_2fa.go): verifies the
// TOTP code against the pending secret and enables 2FA.
func (h *Handler) APIProfile2FAEnable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TOTPCode string `json:"totp_code"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	u, err := h.st.GetUserByID(r.Context(), h.currentUser(r).ID)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "internal", "读取用户信息失败")
		return
	}
	if u.TOTPPendingSecret == "" {
		apiErr(w, http.StatusBadRequest, "validation", "没有待启用的双重验证配置")
		return
	}

	code := req.TOTPCode
	if !verifyTOTP(u.TOTPPendingSecret, code, time.Now()) {
		apiErr(w, http.StatusBadRequest, "validation", "验证码错误，请重试")
		return
	}
	if err := h.st.EnableTOTP(r.Context(), u.ID); err != nil {
		apiErr(w, http.StatusBadRequest, "validation", "启用双重验证失败")
		return
	}
	saved, err := h.st.GetUserByID(r.Context(), u.ID)
	if err != nil {
		saved = u
	}
	apiOKFlash(w, http.StatusOK, h.profileViewPayload(r, saved), "双重验证已启用")
}

// ── POST /api/v1/profile/2fa/disable ─────────────────────────────────────────

// APIProfile2FADisable mirrors Profile2FADisable (handlers_2fa.go): disables 2FA
// after verifying the current password and/or a TOTP code.
func (h *Handler) APIProfile2FADisable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		TOTPCode        string `json:"totp_code"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	u, err := h.st.GetUserByID(r.Context(), h.currentUser(r).ID)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "internal", "读取用户信息失败")
		return
	}
	if !u.TOTPEnabled || u.TOTPSecret == "" {
		apiErr(w, http.StatusBadRequest, "validation", "双重验证未启用")
		return
	}

	passwordOK := false
	totpOK := false
	currentPass := strings.TrimSpace(req.CurrentPassword)
	totpCode := strings.TrimSpace(req.TOTPCode)

	if store.HasPassword(u) && currentPass != "" {
		passwordOK = h.st.VerifyPassword(u, currentPass)
	}
	if totpCode != "" {
		totpOK = verifyTOTP(u.TOTPSecret, totpCode, time.Now())
	}

	if !(passwordOK || totpOK) {
		if store.HasPassword(u) {
			apiErr(w, http.StatusBadRequest, "validation", "请提供正确的当前密码或动态口令验证码")
		} else {
			apiErr(w, http.StatusBadRequest, "validation", "需要有效的动态口令验证码")
		}
		return
	}
	if err := h.st.DisableTOTP(r.Context(), u.ID); err != nil {
		apiErr(w, http.StatusBadRequest, "validation", "关闭双重验证失败")
		return
	}
	saved, err := h.st.GetUserByID(r.Context(), u.ID)
	if err != nil {
		saved = u
	}
	apiOKFlash(w, http.StatusOK, h.profileViewPayload(r, saved), "双重验证已关闭")
}

// ── POST /api/v1/profile/passkey/{id}/delete ─────────────────────────────────

// APIPasskeyDelete mirrors PasskeyDeleteCredential (handlers_passkey.go):
// deletes one of the current user's passkeys after the required verification.
func (h *Handler) APIPasskeyDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password        string `json:"password"`
		CurrentPassword string `json:"current_password"`
		TOTPCode        string `json:"totp_code"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	u := h.currentUser(r)
	id := r.PathValue("id")
	ctx := r.Context()
	creds, err := h.st.GetPasskeyCredentialsByUserID(ctx, u.ID)
	if err != nil {
		apiErr(w, http.StatusBadRequest, "validation", "删除失败")
		return
	}
	found := false
	for _, c := range creds {
		if c.ID == id {
			found = true
			break
		}
	}
	if !found {
		apiErr(w, http.StatusNotFound, "not_found", "通行密钥不存在")
		return
	}
	hasPassword := store.HasPassword(u)
	hasTOTP := u.TOTPEnabled && u.TOTPSecret != ""
	passkeyCount := len(creds)

	// 无密码账户必须至少保留一个通行密钥。
	if !hasPassword && passkeyCount <= 1 {
		apiErr(w, http.StatusBadRequest, "validation", "无密码账户不能删除最后一个通行密钥")
		return
	}

	// Accept either "password" or "current_password" for the password field,
	// mirroring the form's current_password input.
	currentPass := strings.TrimSpace(req.CurrentPassword)
	if currentPass == "" {
		currentPass = strings.TrimSpace(req.Password)
	}
	totpCode := strings.TrimSpace(req.TOTPCode)
	passwordOK := false
	totpOK := false

	if hasPassword && currentPass != "" {
		passwordOK = h.st.VerifyPassword(u, currentPass)
	}
	if hasTOTP && totpCode != "" {
		totpOK = verifyTOTP(u.TOTPSecret, totpCode, time.Now())
	}

	if hasPassword {
		if !(passwordOK || totpOK) {
			apiErr(w, http.StatusBadRequest, "validation", "请提供有效的密码或动态口令验证码")
			return
		}
	} else {
		// 无密码时：删除前必须通过替代验证方式（动态口令）进行校验。
		if !hasTOTP {
			apiErr(w, http.StatusBadRequest, "validation", "删除通行密钥前请先启用动态口令或设置密码")
			return
		}
		if !totpOK {
			apiErr(w, http.StatusBadRequest, "validation", "需要有效的动态口令验证码")
			return
		}
	}

	if err := h.st.DeletePasskeyCredential(ctx, id); err != nil {
		apiErr(w, http.StatusBadRequest, "validation", "删除失败")
		return
	}
	apiOKFlash(w, http.StatusOK, h.profileViewPayload(r, u), "通行密钥已删除")
}
