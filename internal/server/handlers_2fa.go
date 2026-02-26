package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"transmtf.com/oidc/internal/store"
)

func (h *Handler) startSecondFactor(w http.ResponseWriter, r *http.Request, u *store.User, next string) bool {
	hasTOTP := u != nil && u.TOTPEnabled && u.TOTPSecret != ""
	hasPasskey := u != nil && h.st.CountPasskeysByUserID(r.Context(), u.ID) > 0
	if !hasTOTP && !hasPasskey {
		return false
	}
	chID, err := h.st.CreateLogin2FAChallenge(r.Context(), u.ID, safeNextPath(next, "/profile"))
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "服务器内部错误", err.Error())
		return true
	}
	h.set2FAChallengeCookie(w, chID)
	http.Redirect(w, r, "/login/2fa", http.StatusFound)
	return true
}

func (h *Handler) Login2FAPage(w http.ResponseWriter, r *http.Request) {
	if h.currentUser(r) != nil {
		// Already logged in. If there is a pending 2FA challenge whose UserID
		// matches the current user (e.g. authenticated via external provider that
		// also required 2FA), honour the stored redirect so the OAuth2 authorize
		// flow is not interrupted.
		if chID := h.twoFAChallengeFromRequest(r); chID != "" {
			if ch, err := h.st.GetLogin2FAChallenge(r.Context(), chID); err == nil &&
				ch.UserID == h.currentUser(r).ID {
				h.clear2FAChallengeCookie(w)
				http.Redirect(w, r, safeNextPath(ch.Redirect, "/profile"), http.StatusFound)
				return
			}
		}
		http.Redirect(w, r, "/profile", http.StatusFound)
		return
	}
	chID := h.twoFAChallengeFromRequest(r)
	if chID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	ch, err := h.st.GetLogin2FAChallenge(r.Context(), chID)
	if err != nil {
		h.clear2FAChallengeCookie(w)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	u, err := h.st.GetUserByID(r.Context(), ch.UserID)
	if err != nil {
		h.clear2FAChallengeCookie(w)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	d := h.pageData(r, "双重验证")
	d.Data = map[string]any{
		"Email":      u.Email,
		"HasTOTP":    u.TOTPEnabled && u.TOTPSecret != "",
		"HasPasskey": h.st.CountPasskeysByUserID(r.Context(), u.ID) > 0,
	}
	h.render(w, "login_2fa", d)
}

func (h *Handler) Login2FAPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	chID := h.twoFAChallengeFromRequest(r)
	if chID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	ch, err := h.st.GetLogin2FAChallenge(r.Context(), chID)
	if err != nil {
		h.clear2FAChallengeCookie(w)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	u, err := h.st.GetUserByID(r.Context(), ch.UserID)
	if err != nil || !u.Active || !u.TOTPEnabled || u.TOTPSecret == "" {
		h.clear2FAChallengeCookie(w)
		_ = h.st.DeleteLogin2FAChallenge(r.Context(), chID)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	code := r.FormValue("totp_code")
	if !verifyTOTP(u.TOTPSecret, code, time.Now()) {
		d := h.pageData(r, "双重验证")
		d.IsError = true
		d.Flash = "验证码错误，请重试"
		d.Data = map[string]any{
			"Email":      u.Email,
			"HasTOTP":    u.TOTPEnabled && u.TOTPSecret != "",
			"HasPasskey": h.st.CountPasskeysByUserID(r.Context(), u.ID) > 0,
		}
		h.render(w, "login_2fa", d)
		return
	}

	// Consume the challenge atomically to prevent replay/race logins.
	if _, err := h.st.ConsumeLogin2FAChallenge(r.Context(), chID); err != nil {
		h.clear2FAChallengeCookie(w)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	h.clear2FAChallengeCookie(w)

	if u.RequirePasswordChange {
		sid, _ := h.st.CreateSession(r.Context(), u.ID)
		h.setSessionCookie(w, sid)
		target := "/profile/change-password"
		if next := safeNextPath(ch.Redirect, ""); next != "" && next != "/profile" {
			target += "?next=" + url.QueryEscape(next)
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	sid, err := h.st.CreateSession(r.Context(), u.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "会话创建失败", err.Error())
		return
	}
	h.setSessionCookie(w, sid)
	http.Redirect(w, r, safeNextPath(ch.Redirect, "/profile"), http.StatusFound)
}

func (h *Handler) Profile2FAStart(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	u := h.currentUser(r)
	if u.TOTPEnabled {
		h.renderProfileWith2FA(w, r, "双重验证已启用", true)
		return
	}

	secret, err := newTOTPSecret()
	if err != nil {
		h.renderProfileWith2FA(w, r, "无法生成动态口令密钥", true)
		return
	}
	if err := h.st.SavePendingTOTPSecret(r.Context(), u.ID, secret); err != nil {
		h.renderProfileWith2FA(w, r, "保存双重验证配置失败", true)
		return
	}
	http.Redirect(w, r, "/profile?flash=已生成动态口令密钥，请继续完成启用", http.StatusFound)
}

func (h *Handler) Profile2FAEnable(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	u, err := h.st.GetUserByID(r.Context(), h.currentUser(r).ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "读取用户信息失败", err.Error())
		return
	}
	if u.TOTPPendingSecret == "" {
		h.renderProfileWith2FA(w, r, "没有待启用的双重验证配置", true)
		return
	}

	code := r.FormValue("totp_code")
	if !verifyTOTP(u.TOTPPendingSecret, code, time.Now()) {
		h.renderProfileWith2FA(w, r, "验证码错误，请重试", true)
		return
	}
	if err := h.st.EnableTOTP(r.Context(), u.ID); err != nil {
		h.renderProfileWith2FA(w, r, "启用双重验证失败", true)
		return
	}
	http.Redirect(w, r, "/profile?flash=双重验证已启用", http.StatusFound)
}

func (h *Handler) Profile2FADisable(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	u, err := h.st.GetUserByID(r.Context(), h.currentUser(r).ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "读取用户信息失败", err.Error())
		return
	}
	if !u.TOTPEnabled || u.TOTPSecret == "" {
		h.renderProfileWith2FA(w, r, "双重验证未启用", true)
		return
	}

	passwordOK := false
	totpOK := false
	currentPass := strings.TrimSpace(r.FormValue("current_password"))
	totpCode := strings.TrimSpace(r.FormValue("totp_code"))

	if store.HasPassword(u) && currentPass != "" {
		passwordOK = h.st.VerifyPassword(u, currentPass)
	}
	if totpCode != "" {
		totpOK = verifyTOTP(u.TOTPSecret, totpCode, time.Now())
	}

	if !(passwordOK || totpOK) {
		if store.HasPassword(u) {
			h.renderProfileWith2FA(w, r, "请提供正确的当前密码或动态口令验证码", true)
		} else {
			h.renderProfileWith2FA(w, r, "需要有效的动态口令验证码", true)
		}
		return
	}
	if err := h.st.DisableTOTP(r.Context(), u.ID); err != nil {
		h.renderProfileWith2FA(w, r, "关闭双重验证失败", true)
		return
	}
	http.Redirect(w, r, "/profile?flash=双重验证已关闭", http.StatusFound)
}

func (h *Handler) renderProfileWith2FA(w http.ResponseWriter, r *http.Request, flash string, isErr bool) {
	u, err := h.st.GetUserByID(r.Context(), h.currentUser(r).ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "读取用户信息失败", err.Error())
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), ctxUser, u))
	d := h.pageData(r, "个人资料")
	d.Flash = flash
	d.IsError = isErr

	ctx := r.Context()
	data := map[string]any{
		"Passkeys":     nil,
		"HasPassword":  store.HasPassword(u),
		"PasskeyCount": h.st.CountPasskeysByUserID(ctx, u.ID),
	}
	passkeys, _ := h.st.GetPasskeyCredentialsByUserID(ctx, u.ID)
	data["Passkeys"] = passkeys
	if u.TOTPPendingSecret != "" {
		siteName := orDefault(h.st.GetSetting(ctx, "site_name"), "团队站点")
		data["PendingSecret"] = u.TOTPPendingSecret
		data["PendingURI"] = buildTOTPUri(siteName, u.Email, u.TOTPPendingSecret)
	}
	d.Data = data
	h.render(w, "profile", d)
}
