package server

import (
	"context"
	"net/http"
	"time"

	"transmtf.com/oidc/internal/store"
)

func (h *Handler) startSecondFactor(w http.ResponseWriter, r *http.Request, u *store.User, next string) bool {
	if u == nil || !u.TOTPEnabled || u.TOTPSecret == "" {
		return false
	}
	chID, err := h.st.CreateLogin2FAChallenge(r.Context(), u.ID, safeNextPath(next, "/profile"))
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "服务器错误", err.Error())
		return true
	}
	h.set2FAChallengeCookie(w, chID)
	http.Redirect(w, r, "/login/2fa", http.StatusFound)
	return true
}

func (h *Handler) Login2FAPage(w http.ResponseWriter, r *http.Request) {
	if h.currentUser(r) != nil {
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

	d := h.pageData(r, "两步验证")
	d.Data = map[string]any{
		"Email": u.Email,
	}
	h.render(w, "login_2fa", d)
}

func (h *Handler) Login2FAPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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
		d := h.pageData(r, "两步验证")
		d.IsError = true
		d.Flash = "验证码错误，请重试"
		d.Data = map[string]any{"Email": u.Email}
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
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	u := h.currentUser(r)
	if u.TOTPEnabled {
		h.renderProfileWith2FA(w, r, "2FA 已启用，无需重复开启", true)
		return
	}
	currentPass := r.FormValue("current_password")
	if !h.st.VerifyPassword(u, currentPass) {
		h.renderProfileWith2FA(w, r, "当前密码错误", true)
		return
	}

	secret, err := newTOTPSecret()
	if err != nil {
		h.renderProfileWith2FA(w, r, "无法生成 2FA 密钥", true)
		return
	}
	if err := h.st.SavePendingTOTPSecret(r.Context(), u.ID, secret); err != nil {
		h.renderProfileWith2FA(w, r, "保存 2FA 配置失败", true)
		return
	}
	h.renderProfileWith2FA(w, r, "请用认证器扫描下方密钥，并输入验证码确认启用", false)
}

func (h *Handler) Profile2FAEnable(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	u, err := h.st.GetUserByID(r.Context(), h.currentUser(r).ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "用户读取失败", err.Error())
		return
	}
	if u.TOTPPendingSecret == "" {
		h.renderProfileWith2FA(w, r, "没有待启用的 2FA 配置", true)
		return
	}

	code := r.FormValue("totp_code")
	if !verifyTOTP(u.TOTPPendingSecret, code, time.Now()) {
		h.renderProfileWith2FA(w, r, "验证码错误，请重试", true)
		return
	}
	if err := h.st.EnableTOTP(r.Context(), u.ID); err != nil {
		h.renderProfileWith2FA(w, r, "启用 2FA 失败", true)
		return
	}
	h.renderProfileWith2FA(w, r, "2FA 已启用", false)
}

func (h *Handler) Profile2FADisable(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	u, err := h.st.GetUserByID(r.Context(), h.currentUser(r).ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "用户读取失败", err.Error())
		return
	}
	if !u.TOTPEnabled || u.TOTPSecret == "" {
		h.renderProfileWith2FA(w, r, "2FA 尚未启用", true)
		return
	}
	if !h.st.VerifyPassword(u, r.FormValue("current_password")) {
		h.renderProfileWith2FA(w, r, "当前密码错误", true)
		return
	}
	if !verifyTOTP(u.TOTPSecret, r.FormValue("totp_code"), time.Now()) {
		h.renderProfileWith2FA(w, r, "验证码错误", true)
		return
	}
	if err := h.st.DisableTOTP(r.Context(), u.ID); err != nil {
		h.renderProfileWith2FA(w, r, "关闭 2FA 失败", true)
		return
	}
	h.renderProfileWith2FA(w, r, "2FA 已关闭", false)
}

func (h *Handler) renderProfileWith2FA(w http.ResponseWriter, r *http.Request, flash string, isErr bool) {
	u, err := h.st.GetUserByID(r.Context(), h.currentUser(r).ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "用户读取失败", err.Error())
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), ctxUser, u))
	d := h.pageData(r, "个人资料")
	d.Flash = flash
	d.IsError = isErr
	if u.TOTPPendingSecret != "" {
		d.Data = map[string]any{
			"PendingSecret": u.TOTPPendingSecret,
			"PendingURI":    buildTOTPUri(orDefault(h.st.GetSetting(r.Context(), "site_name"), "Team TransMTF"), u.Email, u.TOTPPendingSecret),
		}
	}
	h.render(w, "profile", d)
}
