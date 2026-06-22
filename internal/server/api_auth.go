package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"transmtf.com/oidc/internal/store"
)

// authProviderDTO is a safe external-login provider summary for the login page.
type authProviderDTO struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
	Icon string `json:"icon"`
}

func registerAuthAPIRoutes(mux *http.ServeMux, h *Handler) {
	mux.HandleFunc("POST /api/v1/login", h.requireAPICSRF(h.APILogin))
	mux.HandleFunc("POST /api/v1/register", h.requireAPICSRF(h.APIRegister))
	mux.HandleFunc("POST /api/v1/logout", h.requireAPICSRF(h.APILogout))
	mux.HandleFunc("POST /api/v1/forgot-password", h.requireAPICSRF(h.APIForgotPassword))
	mux.HandleFunc("POST /api/v1/reset-password", h.requireAPICSRF(h.APIResetPassword))
	mux.HandleFunc("POST /api/v1/verify-email", h.requireAPICSRF(h.APIVerifyEmail))
	mux.HandleFunc("POST /api/v1/verify-email/resend", h.requireAPICSRF(h.APIVerifyEmailResend))
	mux.HandleFunc("GET /api/v1/login/providers", h.APILoginProviders)
	mux.HandleFunc("GET /api/v1/login/oidc-challenge", h.APILoginOIDCChallenge)
	// 2FA verify endpoints live under /login/2fa so the path-scoped tmtf_2fa
	// cookie (Path=/login/2fa) is sent. NOT under /api/v1.
	mux.HandleFunc("GET /login/2fa/status", h.APILogin2FAStatus)
	mux.HandleFunc("POST /login/2fa/verify", h.requireAPICSRF(h.APILogin2FAVerify))
}

// APILogin authenticates email+password and returns a discriminated status so
// the SPA can branch: "ok" | "two_factor" | "email_unverified" | "password_change".
func (h *Handler) APILogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email         string `json:"email"`
		Password      string `json:"password"`
		Next          string `json:"next"`
		OIDCChallenge string `json:"oidc_challenge"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	email := strings.TrimSpace(req.Email)
	next := safeNextPath(req.Next, "/profile")
	oidcChallenge := strings.TrimSpace(req.OIDCChallenge)
	ctx := r.Context()

	u, err := h.st.GetUserByEmail(ctx, email)
	if err != nil || !h.st.VerifyPassword(u, req.Password) || !u.Active {
		apiErr(w, http.StatusUnauthorized, "invalid_credentials", "邮箱或密码错误")
		return
	}
	if !u.EmailVerified {
		apiOK(w, http.StatusOK, map[string]any{"status": "email_unverified", "email": email})
		return
	}
	if oidcChallenge != "" {
		challengeNext, linkErr := h.consumeOIDCLoginChallengeAndLink(ctx, u, oidcChallenge)
		if linkErr != nil {
			apiErr(w, http.StatusBadRequest, "oidc_link_failed", linkErr.Error())
			return
		}
		if challengeNext != "" {
			next = challengeNext
		}
	}

	// Second factor required?
	hasTOTP := u.TOTPEnabled && u.TOTPSecret != ""
	hasPasskey := h.st.CountPasskeysByUserID(ctx, u.ID) > 0
	if hasTOTP || hasPasskey {
		chID, err := h.st.CreateLogin2FAChallenge(ctx, u.ID, safeNextPath(next, "/profile"))
		if err != nil {
			apiErr(w, http.StatusInternalServerError, "server_error", "服务器内部错误")
			return
		}
		h.set2FAChallengeCookie(w, chID)
		apiOK(w, http.StatusOK, map[string]any{"status": "two_factor"})
		return
	}

	if u.RequirePasswordChange {
		sid, _ := h.st.CreateSession(ctx, u.ID)
		h.setSessionCookie(w, sid)
		target := "/profile/change-password"
		if next != "" && next != "/profile" {
			target += "?next=" + url.QueryEscape(next)
		}
		apiOK(w, http.StatusOK, map[string]any{"status": "password_change", "redirect": target})
		return
	}

	sid, err := h.st.CreateSession(ctx, u.ID)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "server_error", "服务器内部错误")
		return
	}
	h.setSessionCookie(w, sid)
	apiOK(w, http.StatusOK, map[string]any{"status": "ok", "redirect": next})
}

func (h *Handler) APIRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email         string `json:"email"`
		Password      string `json:"password"`
		Confirm       string `json:"confirm"`
		DisplayName   string `json:"display_name"`
		Next          string `json:"next"`
		OIDCChallenge string `json:"oidc_challenge"`
		AgreeTOS      bool   `json:"agree_tos"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	email := strings.TrimSpace(req.Email)
	name := strings.TrimSpace(req.DisplayName)
	oidcChallenge := strings.TrimSpace(req.OIDCChallenge)
	ctx := r.Context()

	_, _, challengeErr := h.loadOIDCLoginChallenge(ctx, oidcChallenge)
	if oidcChallenge != "" && challengeErr != nil {
		apiErr(w, http.StatusBadRequest, "oidc_expired", "外部登录流程已过期，请重新发起授权登录。")
		return
	}
	fields := map[string]string{}
	if email == "" {
		fields["email"] = "请填写邮箱"
	}
	if name == "" {
		fields["display_name"] = "请填写显示名称"
	}
	if req.Password == "" {
		fields["password"] = "请填写密码"
	} else if len(req.Password) < 8 {
		fields["password"] = "密码至少需要8位"
	} else if req.Password != req.Confirm {
		fields["confirm"] = "两次输入的密码不一致"
	}
	if !req.AgreeTOS {
		fields["agree_tos"] = "请阅读并同意《服务条款》与《隐私政策》后再注册"
	}
	if len(fields) > 0 {
		apiFieldErr(w, fields, "请检查表单填写")
		return
	}

	var (
		u   *store.User
		err error
	)
	if oidcChallenge != "" {
		// External-identity registration: create without a deadline; the account is
		// only granted the OIDC exemption if the identity actually links (below).
		u, err = h.st.CreateUserWithEmailVerified(ctx, email, req.Password, name, "user", false)
	} else {
		// Pure e-mail self-registration: arm the verify-or-purge deadline atomically
		// with account creation, so it can never be unverified-without-deadline.
		u, err = h.st.CreateSelfRegisteredUser(ctx, email, req.Password, name, unverifiedAccountTTL)
	}
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			apiErr(w, http.StatusConflict, "conflict", "邮箱已被注册")
		} else {
			apiErr(w, http.StatusBadRequest, "validation", "注册失败："+err.Error())
		}
		return
	}

	if oidcChallenge != "" {
		if _, linkErr := h.consumeOIDCLoginChallengeAndLink(ctx, u, oidcChallenge); linkErr != nil {
			// Binding failed: this is a stranded e-mail registration, not an OIDC
			// account, so it must still verify or be purged — arm the deadline.
			if derr := h.st.SetVerifyDeadline(ctx, u.ID, unverifiedAccountTTL); derr != nil {
				log.Printf("register: arm verify deadline for unbound %s: %v", u.ID, derr)
			}
			apiErr(w, http.StatusBadRequest, "oidc_link_failed", "账号已创建，但外部登录绑定失败："+linkErr.Error())
			return
		}
		// Identity linked: the account is reachable via the provider and stays exempt
		// from unverified-email auto-deletion (no deadline), like OIDC auto-registered
		// accounts.
	}

	token, err := h.st.CreateEmailVerification(ctx, u.ID)
	if err != nil {
		apiOKFlash(w, http.StatusOK, map[string]any{"status": "init_failed", "email": email}, "注册成功，但验证邮件初始化失败，请重新发送。")
		return
	}
	go h.sendVerificationEmail(context.Background(), u.Email, u.DisplayName, token)
	apiOKFlash(w, http.StatusOK, map[string]any{"status": "sent", "email": email}, "注册成功！请查收验证邮件。")
}

func (h *Handler) APILogout(w http.ResponseWriter, r *http.Request) {
	if sid := h.sessionFromRequest(r); sid != "" {
		_ = h.st.DeleteSession(r.Context(), sid)
	}
	h.clearSessionCookie(w)
	h.clear2FAChallengeCookie(w)
	apiOK(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) APIForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Next  string `json:"next"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	ctx := r.Context()

	u, err := h.st.GetUserByEmail(ctx, email)
	if err != nil {
		// Generic feedback to avoid account enumeration.
		apiOKFlash(w, http.StatusOK, map[string]any{"sent": true}, "如果该邮箱已注册，系统已发送重置密码邮件。")
		return
	}
	token, err := h.st.CreatePasswordReset(ctx, u.ID, 7*24*time.Hour, 30*time.Minute)
	if err != nil {
		if errors.Is(err, store.ErrPasswordResetTooSoon) {
			apiErr(w, http.StatusTooManyRequests, "rate_limited", "7 天内只能发起一次找回密码，请联系管理员。")
			return
		}
		apiErr(w, http.StatusInternalServerError, "server_error", "发送失败，请稍后重试。")
		return
	}
	go h.sendForgotPasswordEmail(context.Background(), u.Email, u.DisplayName, token)
	apiOKFlash(w, http.StatusOK, map[string]any{"sent": true}, "重置密码邮件已发送，请查收。")
}

func (h *Handler) APIResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token           string `json:"token"`
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	token := strings.TrimSpace(req.Token)
	if token == "" {
		apiErr(w, http.StatusBadRequest, "invalid_token", "重置链接无效，请重新申请找回密码。")
		return
	}
	if len(req.NewPassword) < 8 {
		apiFieldErr(w, map[string]string{"new_password": "新密码至少 8 位。"}, "新密码至少 8 位。")
		return
	}
	if req.NewPassword != req.ConfirmPassword {
		apiFieldErr(w, map[string]string{"confirm_password": "两次输入的密码不一致。"}, "两次输入的密码不一致。")
		return
	}
	if _, err := h.st.ConsumePasswordReset(r.Context(), token, req.NewPassword); err != nil {
		if errors.Is(err, store.ErrPasswordResetTokenExpired) {
			apiErr(w, http.StatusBadRequest, "token_expired", "重置链接已过期，请重新申请找回密码。")
			return
		}
		apiErr(w, http.StatusBadRequest, "reset_failed", "重置失败，请稍后重试。")
		return
	}
	apiOKFlash(w, http.StatusOK, map[string]any{"redirect": "/login"}, "密码已重置，请使用新密码登录。")
}

func (h *Handler) APIVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	token := strings.TrimSpace(req.Token)
	if token == "" {
		apiErr(w, http.StatusBadRequest, "invalid_token", "验证链接无效")
		return
	}
	if h.currentUser(r) != nil {
		apiErr(w, http.StatusConflict, "already_logged_in", "请先退出登录再验证新账号邮箱")
		return
	}
	u, err := h.st.ConsumeEmailVerification(r.Context(), token)
	if err != nil {
		apiErr(w, http.StatusBadRequest, "invalid_token", "验证链接无效或已过期，请重新发送验证邮件。")
		return
	}
	autoLogin := false
	if u.Active {
		if sid, err := h.st.CreateSession(r.Context(), u.ID); err == nil {
			h.setSessionCookie(w, sid)
			autoLogin = true
		}
	}
	apiOKFlash(w, http.StatusOK, map[string]any{"verified": true, "autoLoggedIn": autoLogin}, "邮箱验证成功，欢迎加入！")
}

func (h *Handler) APIVerifyEmailResend(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	email := strings.TrimSpace(req.Email)
	ctx := r.Context()
	u, err := h.st.GetUserByEmail(ctx, email)
	// Single generic message for all cases to avoid email enumeration.
	if err != nil || u.EmailVerified {
		apiOKFlash(w, http.StatusOK, map[string]any{"sent": true}, "如果该邮箱已注册且未验证，验证邮件已重新发送，请查收。")
		return
	}
	token, err := h.st.CreateEmailVerification(ctx, u.ID)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "server_error", "发送失败，请稍后重试。")
		return
	}
	go h.sendVerificationEmail(context.Background(), u.Email, u.DisplayName, token)
	apiOKFlash(w, http.StatusOK, map[string]any{"sent": true}, "如果该邮箱已注册且未验证，验证邮件已重新发送，请查收。")
}

func (h *Handler) APILoginProviders(w http.ResponseWriter, r *http.Request) {
	providers, _ := h.st.ListEnabledOIDCProviders(r.Context())
	out := make([]authProviderDTO, 0, len(providers))
	for _, p := range providers {
		out = append(out, authProviderDTO{Slug: p.Slug, Name: p.Name, Icon: p.Icon})
	}
	apiOK(w, http.StatusOK, out)
}

func (h *Handler) APILoginOIDCChallenge(w http.ResponseWriter, r *http.Request) {
	challenge := strings.TrimSpace(r.URL.Query().Get("challenge"))
	if challenge == "" {
		apiErr(w, http.StatusBadRequest, "invalid_request", "缺少 challenge 参数")
		return
	}
	ch, providerName, err := h.loadOIDCLoginChallenge(r.Context(), challenge)
	if err != nil {
		apiErr(w, http.StatusNotFound, "oidc_expired", "外部登录流程已过期，请重新发起授权登录。")
		return
	}
	apiOK(w, http.StatusOK, map[string]any{
		"challenge":     ch.ID,
		"provider":      ch.Provider,
		"providerName":  providerName,
		"profileName":   ch.ProfileName,
		"profileEmail":  ch.ProfileEmail,
		"profileAvatar": ch.ProfileAvatar,
	})
}

// APILogin2FAStatus returns the pending second-factor options. The tmtf_2fa
// cookie (Path=/login/2fa) is required, hence this lives under /login/2fa.
func (h *Handler) APILogin2FAStatus(w http.ResponseWriter, r *http.Request) {
	if h.currentUser(r) != nil {
		apiOK(w, http.StatusOK, map[string]any{"status": "already_authenticated", "redirect": "/profile"})
		return
	}
	chID := h.twoFAChallengeFromRequest(r)
	if chID == "" {
		apiErr(w, http.StatusBadRequest, "no_challenge", "登录会话已过期，请重新登录")
		return
	}
	ch, err := h.st.GetLogin2FAChallenge(r.Context(), chID)
	if err != nil {
		h.clear2FAChallengeCookie(w)
		apiErr(w, http.StatusBadRequest, "no_challenge", "登录会话已过期，请重新登录")
		return
	}
	u, err := h.st.GetUserByID(r.Context(), ch.UserID)
	if err != nil {
		h.clear2FAChallengeCookie(w)
		apiErr(w, http.StatusBadRequest, "no_challenge", "登录会话已过期，请重新登录")
		return
	}
	apiOK(w, http.StatusOK, map[string]any{
		"email":      u.Email,
		"hasTOTP":    u.TOTPEnabled && u.TOTPSecret != "",
		"hasPasskey": h.st.CountPasskeysByUserID(r.Context(), u.ID) > 0,
	})
}

func (h *Handler) APILogin2FAVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TOTPCode string `json:"totp_code"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	chID := h.twoFAChallengeFromRequest(r)
	if chID == "" {
		apiErr(w, http.StatusBadRequest, "no_challenge", "登录会话已过期，请重新登录")
		return
	}
	ch, err := h.st.GetLogin2FAChallenge(r.Context(), chID)
	if err != nil {
		h.clear2FAChallengeCookie(w)
		apiErr(w, http.StatusBadRequest, "no_challenge", "登录会话已过期，请重新登录")
		return
	}
	u, err := h.st.GetUserByID(r.Context(), ch.UserID)
	if err != nil || !u.Active || !u.TOTPEnabled || u.TOTPSecret == "" {
		h.clear2FAChallengeCookie(w)
		_ = h.st.DeleteLogin2FAChallenge(r.Context(), chID)
		apiErr(w, http.StatusBadRequest, "invalid_challenge", "登录会话已过期，请重新登录")
		return
	}
	if !verifyTOTP(u.TOTPSecret, strings.TrimSpace(req.TOTPCode), time.Now()) {
		apiErr(w, http.StatusBadRequest, "invalid_code", "验证码错误，请重试")
		return
	}
	if _, err := h.st.ConsumeLogin2FAChallenge(r.Context(), chID); err != nil {
		h.clear2FAChallengeCookie(w)
		apiErr(w, http.StatusBadRequest, "invalid_challenge", "登录会话已过期，请重新登录")
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
		apiOK(w, http.StatusOK, map[string]any{"status": "password_change", "redirect": target})
		return
	}
	sid, err := h.st.CreateSession(r.Context(), u.ID)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "server_error", "会话创建失败")
		return
	}
	h.setSessionCookie(w, sid)
	apiOK(w, http.StatusOK, map[string]any{"status": "ok", "redirect": safeNextPath(ch.Redirect, "/profile")})
}
