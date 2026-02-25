package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"transmtf.com/oidc/internal/store"
)

func (h *Handler) loadOIDCLoginChallenge(ctx context.Context, challengeID string) (*store.OIDCLoginChallenge, string, error) {
	ch, err := h.st.GetOIDCLoginChallenge(ctx, strings.TrimSpace(challengeID))
	if err != nil {
		return nil, "", err
	}
	providerName := ch.Provider
	if p, pErr := h.st.GetOIDCProviderBySlug(ctx, ch.Provider); pErr == nil && p != nil {
		providerName = p.Name
	}
	return ch, providerName, nil
}

func (h *Handler) appendOIDCChallengeToLoginData(ctx context.Context, data map[string]any, challengeID string) error {
	if strings.TrimSpace(challengeID) == "" {
		return nil
	}
	ch, providerName, err := h.loadOIDCLoginChallenge(ctx, challengeID)
	if err != nil {
		return err
	}
	data["OIDCChallenge"] = ch.ID
	data["OIDCProviderName"] = providerName
	return nil
}

func (h *Handler) appendOIDCChallengeToRegisterData(ctx context.Context, data map[string]any, challengeID string) error {
	if strings.TrimSpace(challengeID) == "" {
		return nil
	}
	ch, providerName, err := h.loadOIDCLoginChallenge(ctx, challengeID)
	if err != nil {
		return err
	}
	data["OIDCChallenge"] = ch.ID
	data["OIDCProviderName"] = providerName
	data["OIDCProviderSlug"] = ch.Provider
	if strings.TrimSpace(ch.ProfileName) != "" {
		data["PrefillDisplayName"] = strings.TrimSpace(ch.ProfileName)
	}
	if strings.TrimSpace(ch.ProfileEmail) != "" {
		data["PrefillEmail"] = strings.TrimSpace(ch.ProfileEmail)
	}
	if strings.TrimSpace(ch.ProfileAvatar) != "" {
		data["PrefillAvatar"] = strings.TrimSpace(ch.ProfileAvatar)
	}
	return nil
}

func (h *Handler) Home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		h.renderError(w, r, http.StatusNotFound, "页面不存在", r.URL.Path)
		return
	}
	ctx := r.Context()
	projects, _ := h.st.ListProjects(ctx)
	links, _ := h.st.ListFriendLinks(ctx)
	d := h.pageData(r, "首页")
	d.Data = map[string]any{
		"Projects": projects,
		"Links":    links,
	}
	h.render(w, "home", d)
}

func (h *Handler) LoginPage(w http.ResponseWriter, r *http.Request) {
	if h.currentUser(r) != nil {
		http.Redirect(w, r, safeNextPath(r.URL.Query().Get("next"), "/profile"), http.StatusFound)
		return
	}
	providers, _ := h.st.ListEnabledOIDCProviders(r.Context())
	d := h.pageData(r, "登录")
	next := safeNextPath(r.URL.Query().Get("next"), "")
	oidcChallenge := strings.TrimSpace(r.URL.Query().Get("oidc_challenge"))
	if flash := strings.TrimSpace(r.URL.Query().Get("flash")); flash != "" {
		d.Flash = flash
		d.IsError = r.URL.Query().Get("err") == "1"
	}
	data := map[string]any{
		"Next":      next,
		"Providers": providers,
	}
	if err := h.appendOIDCChallengeToLoginData(r.Context(), data, oidcChallenge); err != nil {
		d.Flash = "外部登录流程已过期，请重新发起授权登录。"
		d.IsError = true
	}
	d.Data = data
	h.render(w, "login", d)
}

func (h *Handler) LoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	pass := r.FormValue("password")
	next := safeNextPath(r.FormValue("next"), "/profile")
	oidcChallenge := strings.TrimSpace(r.FormValue("oidc_challenge"))

	ctx := r.Context()
	renderLoginErr := func(msg string) {
		providers, _ := h.st.ListEnabledOIDCProviders(ctx)
		d := h.pageData(r, "登录")
		d.Flash = msg
		d.IsError = true
		data := map[string]any{"Next": next, "Providers": providers}
		if err := h.appendOIDCChallengeToLoginData(ctx, data, oidcChallenge); err != nil {
			d.Flash = "外部登录流程已过期，请重新发起授权登录。"
		}
		d.Data = data
		h.render(w, "login", d)
	}

	u, err := h.st.GetUserByEmail(ctx, email)
	if err != nil || !h.st.VerifyPassword(u, pass) || !u.Active {
		renderLoginErr("邮箱或密码错误")
		return
	}

	// Email verification check.
	if !u.EmailVerified {
		providers, _ := h.st.ListEnabledOIDCProviders(ctx)
		d := h.pageData(r, "登录")
		d.Flash = "邮箱尚未验证，请查收验证邮件。"
		d.IsError = true
		data := map[string]any{
			"Next":            next,
			"Providers":       providers,
			"UnverifiedEmail": email,
			"OIDCChallenge":   oidcChallenge,
		}
		if err := h.appendOIDCChallengeToLoginData(ctx, data, oidcChallenge); err != nil {
			d.Flash = "外部登录流程已过期，请重新发起授权登录。"
		}
		d.Data = data
		h.render(w, "login", d)
		return
	}

	if oidcChallenge != "" {
		challengeNext, linkErr := h.consumeOIDCLoginChallengeAndLink(ctx, u, oidcChallenge)
		if linkErr != nil {
			renderLoginErr(linkErr.Error())
			return
		}
		if challengeNext != "" {
			next = challengeNext
		}
	}

	if h.startSecondFactor(w, r, u, next) {
		return
	}

	if u.RequirePasswordChange {
		sid, _ := h.st.CreateSession(ctx, u.ID)
		h.setSessionCookie(w, sid)
		http.Redirect(w, r, "/profile/change-password", http.StatusFound)
		return
	}

	sid, err := h.st.CreateSession(ctx, u.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "服务器内部错误", err.Error())
		return
	}
	h.setSessionCookie(w, sid)
	http.Redirect(w, r, next, http.StatusFound)
}

func (h *Handler) RegisterPage(w http.ResponseWriter, r *http.Request) {
	d := h.pageData(r, "注册")
	data := map[string]any{
		"Next": safeNextPath(r.URL.Query().Get("next"), ""),
	}
	oidcChallenge := strings.TrimSpace(r.URL.Query().Get("oidc_challenge"))
	if err := h.appendOIDCChallengeToRegisterData(r.Context(), data, oidcChallenge); err != nil {
		d.Flash = "外部登录流程已过期，请重新发起授权登录。"
		d.IsError = true
	}
	d.Data = data
	h.render(w, "register", d)
}

func (h *Handler) RegisterPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	pass := r.FormValue("password")
	confirm := r.FormValue("confirm")
	name := strings.TrimSpace(r.FormValue("display_name"))
	next := safeNextPath(r.FormValue("next"), "")
	oidcChallenge := strings.TrimSpace(r.FormValue("oidc_challenge"))

	ctx := r.Context()
	_, _, challengeErr := h.loadOIDCLoginChallenge(ctx, oidcChallenge)

	fail := func(msg string, keepChallenge bool) {
		d := h.pageData(r, "注册")
		d.Flash = msg
		d.IsError = true
		data := map[string]any{
			"Next":               next,
			"PrefillEmail":       email,
			"PrefillDisplayName": name,
		}
		if keepChallenge && oidcChallenge != "" {
			if err := h.appendOIDCChallengeToRegisterData(ctx, data, oidcChallenge); err != nil {
				d.Flash = "外部登录流程已过期，请重新发起授权登录。"
			}
		}
		d.Data = data
		h.render(w, "register", d)
	}

	if oidcChallenge != "" && challengeErr != nil {
		fail("外部登录流程已过期，请重新发起授权登录。", false)
		return
	}
	if email == "" || pass == "" || name == "" {
		fail("请填写所有必填项", oidcChallenge != "")
		return
	}
	if len(pass) < 8 {
		fail("密码至少需要8位", oidcChallenge != "")
		return
	}
	if pass != confirm {
		fail("两次输入的密码不一致", oidcChallenge != "")
		return
	}

	u, err := h.st.CreateUserWithEmailVerified(ctx, email, pass, name, "user", false)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			fail("邮箱已被注册", oidcChallenge != "")
		} else {
			fail("注册失败："+err.Error(), oidcChallenge != "")
		}
		return
	}

	if oidcChallenge != "" {
		if _, linkErr := h.consumeOIDCLoginChallengeAndLink(ctx, u, oidcChallenge); linkErr != nil {
			d := h.pageData(r, "注册结果")
			d.Flash = "账号已创建，但外部登录绑定失败：" + linkErr.Error()
			d.IsError = true
			h.render(w, "error", d)
			return
		}
	}

	token, err := h.st.CreateEmailVerification(ctx, u.ID)
	if err != nil {
		http.Redirect(w, r, verifyEmailURL(email, "init_failed"), http.StatusSeeOther)
		return
	}
	go h.sendVerificationEmail(context.Background(), u.Email, u.DisplayName, token)

	http.Redirect(w, r, verifyEmailURL(email, "sent"), http.StatusSeeOther)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	sid := h.sessionFromRequest(r)
	if sid != "" {
		_ = h.st.DeleteSession(r.Context(), sid)
	}
	h.clearSessionCookie(w)
	h.clear2FAChallengeCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handler) buildProfileViewData(ctx context.Context, u *store.User) map[string]any {
	data := map[string]any{
		"Passkeys":          nil,
		"HasPassword":       false,
		"PasskeyCount":      0,
		"ExternalProviders": []map[string]any{},
	}
	if u == nil {
		return data
	}

	passkeys, _ := h.st.GetPasskeyCredentialsByUserID(ctx, u.ID)
	data["Passkeys"] = passkeys
	data["HasPassword"] = store.HasPassword(u)
	data["PasskeyCount"] = h.st.CountPasskeysByUserID(ctx, u.ID)
	if u.TOTPPendingSecret != "" {
		siteName := orDefault(h.st.GetSetting(ctx, "site_name"), "团队站点")
		data["PendingSecret"] = u.TOTPPendingSecret
		data["PendingURI"] = buildTOTPUri(siteName, u.Email, u.TOTPPendingSecret)
	}

	identities, _ := h.st.GetUserIdentitiesByUserID(ctx, u.ID)
	boundProviders := map[string]bool{}
	for _, id := range identities {
		boundProviders[id.Provider] = true
	}
	providers, _ := h.st.ListOIDCProviders(ctx)
	items := make([]map[string]any, 0, len(providers))
	for _, p := range providers {
		items = append(items, map[string]any{
			"Slug":    p.Slug,
			"Name":    p.Name,
			"Icon":    p.Icon,
			"Enabled": p.Enabled,
			"Bound":   boundProviders[p.Slug],
		})
	}
	data["ExternalProviders"] = items
	return data
}

func (h *Handler) Profile(w http.ResponseWriter, r *http.Request) {
	u := h.currentUser(r)
	d := h.pageData(r, "个人资料")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = h.buildProfileViewData(r.Context(), u)
	h.render(w, "profile", d)
}

func (h *Handler) ProfilePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	u := h.currentUser(r)
	ctx := r.Context()
	name := strings.TrimSpace(r.FormValue("display_name"))
	avatar := strings.TrimSpace(r.FormValue("avatar_url"))
	newPass := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")
	currentPass := r.FormValue("current_password")

	fail := func(msg string) {
		d := h.pageData(r, "个人资料")
		d.Flash = msg
		d.IsError = true
		d.Data = h.buildProfileViewData(r.Context(), u)
		h.render(w, "profile", d)
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

	if err := h.st.UpdateUser(ctx, u.ID, name, u.Role, u.Active); err != nil {
		fail("保存失败：" + err.Error())
		return
	}
	if avatar != "" {
		_ = h.st.UpdateUserAvatar(ctx, u.ID, avatar)
	}
	if newPass != "" {
		if err := h.st.UpdatePassword(ctx, u.ID, newPass); err != nil {
			fail("密码更新失败")
			return
		}
	}

	http.Redirect(w, r, "/profile?flash=已保存", http.StatusFound)
}

func (h *Handler) ProfileIdentityBind(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	u := h.currentUser(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	slug := r.PathValue("slug")
	ctx := r.Context()
	p, err := h.st.GetOIDCProviderBySlug(ctx, slug)
	if err != nil || !p.Enabled {
		http.Redirect(w, r, "/profile?flash="+url.QueryEscape("该登录方式不可用"), http.StatusFound)
		return
	}
	if _, err := h.st.GetUserIdentityByUserAndProvider(ctx, u.ID, slug); err == nil {
		http.Redirect(w, r, "/profile?flash="+url.QueryEscape("该登录方式已绑定"), http.StatusFound)
		return
	} else if !isErrNoRows(err) {
		http.Redirect(w, r, "/profile?flash="+url.QueryEscape("读取绑定状态失败"), http.StatusFound)
		return
	}

	p.ProviderType = normalizeProviderType(p.ProviderType)
	_ = h.startProviderAuthFlow(w, r, p, "/profile", u.ID)
}

func (h *Handler) ProfileIdentityUnbind(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	u := h.currentUser(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	slug := r.PathValue("slug")
	ctx := r.Context()
	if _, err := h.st.GetUserIdentityByUserAndProvider(ctx, u.ID, slug); err != nil {
		if isErrNoRows(err) {
			http.Redirect(w, r, "/profile?flash="+url.QueryEscape("该登录方式尚未绑定"), http.StatusFound)
			return
		}
		http.Redirect(w, r, "/profile?flash="+url.QueryEscape("读取绑定状态失败"), http.StatusFound)
		return
	}
	affected, err := h.st.DeleteUserIdentityByUserAndProvider(ctx, u.ID, slug)
	if err != nil {
		http.Redirect(w, r, "/profile?flash="+url.QueryEscape("解绑失败"), http.StatusFound)
		return
	}
	if affected == 0 {
		http.Redirect(w, r, "/profile?flash="+url.QueryEscape("该登录方式尚未绑定"), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/profile?flash="+url.QueryEscape("登录方式解绑成功"), http.StatusFound)
}

func (h *Handler) TOSPage(w http.ResponseWriter, r *http.Request) {
	d := h.pageData(r, "服务条款")
	d.Data = h.st.GetSetting(r.Context(), "tos_content")
	h.render(w, "tos", d)
}

func (h *Handler) PrivacyPage(w http.ResponseWriter, r *http.Request) {
	d := h.pageData(r, "隐私政策")
	d.Data = h.st.GetSetting(r.Context(), "privacy_content")
	h.render(w, "privacy", d)
}

// Profile2FAQR serves the pending TOTP secret as a QR code PNG.
func (h *Handler) Profile2FAQR(w http.ResponseWriter, r *http.Request) {
	u := h.currentUser(r)
	if u == nil || u.TOTPPendingSecret == "" {
		http.NotFound(w, r)
		return
	}
	siteName := orDefault(h.st.GetSetting(r.Context(), "site_name"), "团队站点")
	uri := buildTOTPUri(siteName, u.Email, u.TOTPPendingSecret)
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "二维码生成失败", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

// AnnouncementAPI returns the announcement text for a client (empty string, never 404).
func (h *Handler) AnnouncementAPI(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("clientid")
	content := h.st.GetClientAnnouncement(r.Context(), clientID)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, content)
}

// VerifyEmailPage handles GET /verify-email
// If a ?token= query param is present, processes the verification immediately.
// Otherwise shows the "check your email" page.
func (h *Handler) VerifyEmailPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.URL.Query().Get("token")
	email := r.URL.Query().Get("email")
	status := r.URL.Query().Get("status")

	if token != "" {
		u, err := h.st.ConsumeEmailVerification(ctx, token)
		if err != nil {
			d := h.pageData(r, "邮箱验证失败")
			d.Flash = "验证链接无效或已过期，请重新发送验证邮件。"
			d.IsError = true
			d.Data = map[string]any{"Email": email}
			h.render(w, "verify_email", d)
			return
		}
		// Auto-login only when account is active.
		if u.Active {
			if sid, err := h.st.CreateSession(ctx, u.ID); err == nil {
				h.setSessionCookie(w, sid)
			}
		}
		d := h.pageData(r, "邮箱验证成功")
		d.Flash = "邮箱验证成功，欢迎加入！"
		d.Data = map[string]any{"Verified": true}
		h.render(w, "verify_email", d)
		return
	}

	d := h.pageData(r, "验证邮箱")
	switch status {
	case "sent":
		d.Flash = "注册成功！请查收验证邮件。"
	case "resent":
		d.Flash = "如果该邮箱已注册且未验证，验证邮件已重新发送，请查收。"
	case "init_failed":
		d.Flash = "注册成功，但验证邮件初始化失败，请重新发送。"
		d.IsError = true
	case "resend_failed":
		d.Flash = "发送失败，请稍后重试。"
		d.IsError = true
	}
	d.Data = map[string]any{"Email": email}
	h.render(w, "verify_email", d)
}

// VerifyEmailResend handles POST /verify-email/resend
func (h *Handler) VerifyEmailResend(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	ctx := r.Context()

	u, err := h.st.GetUserByEmail(ctx, email)
	// Use a single generic message for all cases to avoid email enumeration.
	if err != nil || u.EmailVerified {
		http.Redirect(w, r, verifyEmailURL(email, "resent"), http.StatusSeeOther)
		return
	}
	token, err := h.st.CreateEmailVerification(ctx, u.ID)
	if err != nil {
		http.Redirect(w, r, verifyEmailURL(email, "resend_failed"), http.StatusSeeOther)
		return
	}
	go h.sendVerificationEmail(context.Background(), u.Email, u.DisplayName, token)
	http.Redirect(w, r, verifyEmailURL(email, "resent"), http.StatusSeeOther)
}

func verifyEmailURL(email, status string) string {
	v := url.Values{}
	if email != "" {
		v.Set("email", email)
	}
	if status != "" {
		v.Set("status", status)
	}
	if len(v) == 0 {
		return "/verify-email"
	}
	return "/verify-email?" + v.Encode()
}

func (h *Handler) ForgotPasswordPage(w http.ResponseWriter, r *http.Request) {
	d := h.pageData(r, "忘记密码")
	if flash := strings.TrimSpace(r.URL.Query().Get("flash")); flash != "" {
		d.Flash = flash
		d.IsError = r.URL.Query().Get("err") == "1"
	}
	d.Data = map[string]any{
		"Next": safeNextPath(r.URL.Query().Get("next"), ""),
	}
	h.render(w, "forgot_password", d)
}

func (h *Handler) ForgotPasswordPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	next := safeNextPath(r.FormValue("next"), "")
	ctx := r.Context()
	redirectWithFlash := func(flash string, isErr bool) {
		v := url.Values{}
		if flash != "" {
			v.Set("flash", flash)
		}
		if isErr {
			v.Set("err", "1")
		}
		if next != "" {
			v.Set("next", next)
		}
		target := "/forgot-password"
		if len(v) > 0 {
			target += "?" + v.Encode()
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
	}

	u, err := h.st.GetUserByEmail(ctx, email)
	// Keep generic feedback for non-existing users.
	if err != nil {
		redirectWithFlash("如果该邮箱已注册，系统已发送重置密码邮件。", false)
		return
	}

	token, err := h.st.CreatePasswordReset(ctx, u.ID, 7*24*time.Hour, 30*time.Minute)
	if err != nil {
		if errors.Is(err, store.ErrPasswordResetTooSoon) {
			redirectWithFlash("7 天内只能发起一次找回密码，请联系管理员。", true)
			return
		}
		redirectWithFlash("发送失败，请稍后重试。", true)
		return
	}
	go h.sendForgotPasswordEmail(context.Background(), u.Email, u.DisplayName, token)
	redirectWithFlash("重置密码邮件已发送，请查收。", false)
}

func (h *Handler) ResetPasswordPage(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	d := h.pageData(r, "重置密码")
	d.Data = map[string]any{"Token": token}
	if token == "" {
		d.Flash = "重置链接无效，请重新申请找回密码。"
		d.IsError = true
	}
	h.render(w, "reset_password", d)
}

func (h *Handler) ResetPasswordPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	token := strings.TrimSpace(r.FormValue("token"))
	pass := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")
	d := h.pageData(r, "重置密码")
	d.Data = map[string]any{"Token": token}
	fail := func(msg string) {
		d.Flash = msg
		d.IsError = true
		h.render(w, "reset_password", d)
	}

	if token == "" {
		fail("重置链接无效，请重新申请找回密码。")
		return
	}
	if len(pass) < 8 {
		fail("新密码至少 8 位。")
		return
	}
	if pass != confirm {
		fail("两次输入的密码不一致。")
		return
	}

	if _, err := h.st.ConsumePasswordReset(r.Context(), token, pass); err != nil {
		switch {
		case errors.Is(err, store.ErrPasswordResetTokenExpired):
			fail("重置链接已过期，请重新申请找回密码。")
		default:
			fail("重置失败，请稍后重试。")
		}
		return
	}

	http.Redirect(w, r, "/login?flash="+url.QueryEscape("密码已重置，请使用新密码登录。")+"&next="+url.QueryEscape("/profile"), http.StatusSeeOther)
}

// ProfileForceChangePage shows the forced password change page.
func (h *Handler) ProfileForceChangePage(w http.ResponseWriter, r *http.Request) {
	u := h.currentUser(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !u.RequirePasswordChange {
		http.Redirect(w, r, "/profile", http.StatusFound)
		return
	}
	d := h.pageData(r, "修改密码")
	h.render(w, "force_change_password", d)
}

// ProfileForceChangePost handles the forced password change form submission.
func (h *Handler) ProfileForceChangePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	u := h.currentUser(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	// Only allow this handler when the flag is actually set.
	if !u.RequirePasswordChange {
		http.Redirect(w, r, "/profile", http.StatusFound)
		return
	}

	newPass := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	fail := func(msg string) {
		d := h.pageData(r, "修改密码")
		d.Flash = msg
		d.IsError = true
		h.render(w, "force_change_password", d)
	}

	if len(newPass) < 8 {
		fail("新密码至少 8 位。")
		return
	}
	if newPass != confirm {
		fail("两次输入的密码不一致。")
		return
	}
	if err := h.st.UpdatePasswordAndClearFlag(r.Context(), u.ID, newPass); err != nil {
		fail("密码更新失败：" + err.Error())
		return
	}
	http.Redirect(w, r, "/profile?flash=密码已更新", http.StatusFound)
}

// ProfileDeletePassword removes the user's password (passkey-only mode).
func (h *Handler) ProfileDeletePassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	u := h.currentUser(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	ctx := r.Context()
	if h.st.CountPasskeysByUserID(ctx, u.ID) == 0 {
		http.Redirect(w, r, "/profile?flash=请先添加通行密钥", http.StatusFound)
		return
	}
	if err := h.st.ClearPassword(ctx, u.ID); err != nil {
		http.Redirect(w, r, "/profile?flash=删除密码失败", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/profile?flash=密码已删除", http.StatusFound)
}
