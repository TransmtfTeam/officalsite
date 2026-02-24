package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"transmtf.com/oidc/internal/store"
)

func (h *Handler) Home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		h.renderError(w, r, http.StatusNotFound, "Not Found", r.URL.Path)
		return
	}
	ctx := r.Context()
	projects, _ := h.st.ListProjects(ctx)
	links, _ := h.st.ListFriendLinks(ctx)
	d := h.pageData(r, "MTF - Team TransMTF")
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
    d := h.pageData(r, "Login")
	d.Data = map[string]any{
		"Next":      safeNextPath(r.URL.Query().Get("next"), ""),
		"Providers": providers,
	}
	h.render(w, "login", d)
}

func (h *Handler) LoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	pass := r.FormValue("password")
	next := safeNextPath(r.FormValue("next"), "/profile")

	ctx := r.Context()
	u, err := h.st.GetUserByEmail(ctx, email)
	if err != nil || !h.st.VerifyPassword(u, pass) || !u.Active {
		providers, _ := h.st.ListEnabledOIDCProviders(ctx)
        d := h.pageData(r, "Login")
		d.Flash = "邮箱或密码错误"
		d.IsError = true
		d.Data = map[string]any{"Next": next, "Providers": providers}
		h.render(w, "login", d)
		return
	}

	// Email verification check.
	if !u.EmailVerified {
		providers, _ := h.st.ListEnabledOIDCProviders(ctx)
		d := h.pageData(r, "Login")
		d.Flash = "邮箱尚未验证，请查收注册时发送的验证邮件。"
		d.IsError = true
		d.Data = map[string]any{
			"Next":            next,
			"Providers":       providers,
			"UnverifiedEmail": email,
		}
		h.render(w, "login", d)
		return
	}

	if h.startSecondFactor(w, r, u, next) {
		return
	}

	sid, err := h.st.CreateSession(ctx, u.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}
	h.setSessionCookie(w, sid)
	http.Redirect(w, r, next, http.StatusFound)
}

func (h *Handler) RegisterPage(w http.ResponseWriter, r *http.Request) {
    d := h.pageData(r, "Register")
	h.render(w, "register", d)
}

func (h *Handler) RegisterPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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

	fail := func(msg string) {
        d := h.pageData(r, "Register")
		d.Flash = msg
		d.IsError = true
		h.render(w, "register", d)
	}

	if email == "" || pass == "" || name == "" {
		fail("Please fill in all required fields")
		return
	}
	if len(pass) < 8 {
		fail("Password must be at least 8 characters")
		return
	}
	if pass != confirm {
		fail("Passwords do not match")
		return
	}

	ctx := r.Context()
	u, err := h.st.CreateUserWithEmailVerified(ctx, email, pass, name, "user", false)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			fail("邮箱已被注册")
		} else {
			fail("注册失败：" + err.Error())
		}
		return
	}

	token, err := h.st.CreateEmailVerification(ctx, u.ID)
	if err != nil {
		d := h.pageData(r, "验证邮箱")
		d.Flash = "注册成功，但验证邮件初始化失败。请使用下方入口重新发送验证邮件。"
		d.IsError = true
		d.Data = map[string]any{"Email": email}
		h.render(w, "verify_email", d)
		return
	}
	go h.sendVerificationEmail(context.Background(), u.Email, u.DisplayName, token)

	d := h.pageData(r, "验证邮箱")
	d.Flash = "注册成功！请查收发送到 " + email + " 的验证邮件，点击链接完成验证后即可登录。"
	d.Data = map[string]any{"Email": email}
	h.render(w, "verify_email", d)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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

func (h *Handler) Profile(w http.ResponseWriter, r *http.Request) {
	u := h.currentUser(r)
	d := h.pageData(r, "Profile")
	ctx := r.Context()
	data := map[string]any{"Passkeys": nil}
	if u != nil {
		passkeys, _ := h.st.GetPasskeyCredentialsByUserID(ctx, u.ID)
		data["Passkeys"] = passkeys
		if u.TOTPPendingSecret != "" {
			siteName := orDefault(h.st.GetSetting(ctx, "site_name"), "Team TransMTF")
			data["PendingSecret"] = u.TOTPPendingSecret
			data["PendingURI"] = buildTOTPUri(siteName, u.Email, u.TOTPPendingSecret)
		}
	}
	d.Data = data
	h.render(w, "profile", d)
}

func (h *Handler) ProfilePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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
		d := h.pageData(r, "Profile")
		d.Flash = msg
		d.IsError = true
		data := map[string]any{"Passkeys": nil}
		if u != nil {
			passkeys, _ := h.st.GetPasskeyCredentialsByUserID(r.Context(), u.ID)
			data["Passkeys"] = passkeys
			if u.TOTPPendingSecret != "" {
				siteName := orDefault(h.st.GetSetting(r.Context(), "site_name"), "Team TransMTF")
				data["PendingSecret"] = u.TOTPPendingSecret
				data["PendingURI"] = buildTOTPUri(siteName, u.Email, u.TOTPPendingSecret)
			}
		}
		d.Data = data
		h.render(w, "profile", d)
	}

	if name == "" {
		fail("Display name cannot be empty")
		return
	}
	// Validate password fields BEFORE any writes to avoid partial updates.
	if newPass != "" {
		if !h.st.VerifyPassword(u, currentPass) {
			fail("当前密码不正确")
			return
		}
		if len(newPass) < 8 {
			fail("New password must be at least 8 characters")
			return
		}
		if newPass != confirm {
			fail("Passwords do not match")
			return
		}
	}

	if err := h.st.UpdateUser(ctx, u.ID, name, u.Role, u.Active); err != nil {
		fail("Save failed: " + err.Error())
		return
	}
	if avatar != "" {
		_ = h.st.UpdateUserAvatar(ctx, u.ID, avatar)
	}
	if newPass != "" {
		if err := h.st.UpdatePassword(ctx, u.ID, newPass); err != nil {
			fail("Password update failed")
			return
		}
	}

	d := h.pageData(r, "Profile")
	d.Flash = "Saved"
	data := map[string]any{"Passkeys": nil}
	if u != nil {
		passkeys, _ := h.st.GetPasskeyCredentialsByUserID(ctx, u.ID)
		data["Passkeys"] = passkeys
		if u.TOTPPendingSecret != "" {
			siteName := orDefault(h.st.GetSetting(ctx, "site_name"), "Team TransMTF")
			data["PendingSecret"] = u.TOTPPendingSecret
			data["PendingURI"] = buildTOTPUri(siteName, u.Email, u.TOTPPendingSecret)
		}
	}
	d.Data = data
	h.render(w, "profile", d)
}

func (h *Handler) TOSPage(w http.ResponseWriter, r *http.Request) {
	d := h.pageData(r, "Terms of Service")
	d.Data = h.st.GetSetting(r.Context(), "tos_content")
	h.render(w, "tos", d)
}

func (h *Handler) PrivacyPage(w http.ResponseWriter, r *http.Request) {
	d := h.pageData(r, "Privacy Policy")
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
	siteName := orDefault(h.st.GetSetting(r.Context(), "site_name"), "Team TransMTF")
	uri := buildTOTPUri(siteName, u.Email, u.TOTPPendingSecret)
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "qr generation failed", http.StatusInternalServerError)
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
	d.Data = map[string]any{"Email": email}
	h.render(w, "verify_email", d)
}

// VerifyEmailResend handles POST /verify-email/resend
func (h *Handler) VerifyEmailResend(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	ctx := r.Context()

	render := func(flash string, isErr bool) {
		d := h.pageData(r, "验证邮箱")
		d.Flash = flash
		d.IsError = isErr
		d.Data = map[string]any{"Email": email}
		h.render(w, "verify_email", d)
	}

	u, err := h.st.GetUserByEmail(ctx, email)
	// Use a single generic message for all cases to avoid email enumeration.
	const genericMsg = "如果该邮箱已注册且未验证，验证邮件已重新发送，请查收。"
	if err != nil || u.EmailVerified {
		render(genericMsg, false)
		return
	}
	token, err := h.st.CreateEmailVerification(ctx, u.ID)
	if err != nil {
		render("发送失败，请稍后再试。", true)
		return
	}
	go h.sendVerificationEmail(context.Background(), u.Email, u.DisplayName, token)
	render(genericMsg, false)
}

func (h *Handler) ForgotPasswordPage(w http.ResponseWriter, r *http.Request) {
	d := h.pageData(r, "忘记密码")
	h.render(w, "forgot_password", d)
}

func (h *Handler) ForgotPasswordPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	ctx := r.Context()
	d := h.pageData(r, "忘记密码")
	render := func(flash string, isErr bool) {
		d.Flash = flash
		d.IsError = isErr
		d.Data = map[string]any{"Email": email}
		h.render(w, "forgot_password", d)
	}

	u, err := h.st.GetUserByEmail(ctx, email)
	// Keep generic feedback for non-existing users.
	if err != nil {
		render("如果该邮箱已注册，系统已发送重置密码邮件。", false)
		return
	}

	token, err := h.st.CreatePasswordReset(ctx, u.ID, 7*24*time.Hour, 30*time.Minute)
	if err != nil {
		if errors.Is(err, store.ErrPasswordResetTooSoon) {
			render("7天内只能发起一次找回密码，请联系管理员修改密码。", true)
			return
		}
		render("发送失败，请稍后再试。", true)
		return
	}
	go h.sendForgotPasswordEmail(context.Background(), u.Email, u.DisplayName, token)
	render("重置密码邮件已发送，请查收。", false)
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
		http.Error(w, "bad request", http.StatusBadRequest)
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
			fail("重置失败，请稍后再试。")
		}
		return
	}

	d = h.pageData(r, "登录")
	d.Flash = "密码已重置，请使用新密码登录。"
	d.Data = map[string]any{"Next": "/profile"}
	h.render(w, "login", d)
}
