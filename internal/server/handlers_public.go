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
	if flash := strings.TrimSpace(r.URL.Query().Get("flash")); flash != "" {
		d.Flash = flash
		d.IsError = r.URL.Query().Get("err") == "1"
	}
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
		d.Flash = "Invalid email or password"
		d.IsError = true
		d.Data = map[string]any{"Next": next, "Providers": providers}
		h.render(w, "login", d)
		return
	}

	// Email verification check.
	if !u.EmailVerified {
		providers, _ := h.st.ListEnabledOIDCProviders(ctx)
		d := h.pageData(r, "Login")
		d.Flash = "Email is not verified. Please check your inbox for the verification email."
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

	if u.RequirePasswordChange {
		sid, _ := h.st.CreateSession(ctx, u.ID)
		h.setSessionCookie(w, sid)
		http.Redirect(w, r, "/profile/change-password", http.StatusFound)
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
			fail("Email is already registered")
		} else {
			fail("Registration failed: " + err.Error())
		}
		return
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
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	ctx := r.Context()
	data := map[string]any{"Passkeys": nil, "HasPassword": false, "PasskeyCount": 0}
	if u != nil {
		passkeys, _ := h.st.GetPasskeyCredentialsByUserID(ctx, u.ID)
		data["Passkeys"] = passkeys
		data["HasPassword"] = store.HasPassword(u)
		data["PasskeyCount"] = h.st.CountPasskeysByUserID(ctx, u.ID)
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
		data := map[string]any{"Passkeys": nil, "HasPassword": false, "PasskeyCount": 0}
		if u != nil {
			passkeys, _ := h.st.GetPasskeyCredentialsByUserID(r.Context(), u.ID)
			data["Passkeys"] = passkeys
			data["HasPassword"] = store.HasPassword(u)
			data["PasskeyCount"] = h.st.CountPasskeysByUserID(r.Context(), u.ID)
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
		if store.HasPassword(u) && !h.st.VerifyPassword(u, currentPass) {
			fail("Current password is incorrect")
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

	http.Redirect(w, r, "/profile?flash=Saved", http.StatusFound)
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
	status := r.URL.Query().Get("status")

	if token != "" {
		u, err := h.st.ConsumeEmailVerification(ctx, token)
		if err != nil {
			d := h.pageData(r, "Email Verification Failed")
			d.Flash = "Verification link is invalid or expired. Please request a new one."
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
		d := h.pageData(r, "Email Verified")
		d.Flash = "Email verification succeeded."
		d.Data = map[string]any{"Verified": true}
		h.render(w, "verify_email", d)
		return
	}

	d := h.pageData(r, "Verify Email")
	switch status {
	case "sent":
		d.Flash = "Registration successful. Please check your email to verify your account."
	case "resent":
		d.Flash = "If this email exists and is unverified, a new verification email has been sent."
	case "init_failed":
		d.Flash = "Registration succeeded, but initializing email verification failed. Please resend verification email."
		d.IsError = true
	case "resend_failed":
		d.Flash = "Sending failed. Please try again later."
		d.IsError = true
	}
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
	d := h.pageData(r, "Forgot Password")
	if flash := strings.TrimSpace(r.URL.Query().Get("flash")); flash != "" {
		d.Flash = flash
		d.IsError = r.URL.Query().Get("err") == "1"
	}
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
	redirectWithFlash := func(flash string, isErr bool) {
		v := url.Values{}
		if flash != "" {
			v.Set("flash", flash)
		}
		if isErr {
			v.Set("err", "1")
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
		redirectWithFlash("If the email is registered, a password reset email has been sent.", false)
		return
	}

	token, err := h.st.CreatePasswordReset(ctx, u.ID, 7*24*time.Hour, 30*time.Minute)
	if err != nil {
		if errors.Is(err, store.ErrPasswordResetTooSoon) {
			redirectWithFlash("Password reset can be requested once every 7 days. Please contact an admin if needed.", true)
			return
		}
		redirectWithFlash("Sending failed. Please try again later.", true)
		return
	}
	go h.sendForgotPasswordEmail(context.Background(), u.Email, u.DisplayName, token)
	redirectWithFlash("Password reset email has been sent. Please check your inbox.", false)
}

func (h *Handler) ResetPasswordPage(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	d := h.pageData(r, "Reset Password")
	d.Data = map[string]any{"Token": token}
	if token == "" {
		d.Flash = "Reset link is invalid. Please request password reset again."
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
	d := h.pageData(r, "Reset Password")
	d.Data = map[string]any{"Token": token}
	fail := func(msg string) {
		d.Flash = msg
		d.IsError = true
		h.render(w, "reset_password", d)
	}

	if token == "" {
		fail("Reset link is invalid. Please request password reset again.")
		return
	}
	if len(pass) < 8 {
		fail("New password must be at least 8 characters.")
		return
	}
	if pass != confirm {
		fail("Passwords do not match.")
		return
	}

	if _, err := h.st.ConsumePasswordReset(r.Context(), token, pass); err != nil {
		switch {
		case errors.Is(err, store.ErrPasswordResetTokenExpired):
			fail("Reset link has expired. Please request password reset again.")
		default:
			fail("Reset failed. Please try again later.")
		}
		return
	}

	http.Redirect(w, r, "/login?flash="+url.QueryEscape("Password has been reset. Please sign in with your new password.")+"&next="+url.QueryEscape("/profile"), http.StatusSeeOther)
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
	d := h.pageData(r, "Change Password")
	h.render(w, "force_change_password", d)
}

// ProfileForceChangePost handles the forced password change form submission.
func (h *Handler) ProfileForceChangePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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
		d := h.pageData(r, "Change Password")
		d.Flash = msg
		d.IsError = true
		h.render(w, "force_change_password", d)
	}

	if len(newPass) < 8 {
		fail("New password must be at least 8 characters.")
		return
	}
	if newPass != confirm {
		fail("Passwords do not match.")
		return
	}
	if err := h.st.UpdatePasswordAndClearFlag(r.Context(), u.ID, newPass); err != nil {
		fail("Password update failed: " + err.Error())
		return
	}
	http.Redirect(w, r, "/profile?flash=Password+updated", http.StatusFound)
}

// ProfileDeletePassword removes the user's password (passkey-only mode).
func (h *Handler) ProfileDeletePassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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
		http.Redirect(w, r, "/profile?flash=Must+have+passkey+first", http.StatusFound)
		return
	}
	if err := h.st.ClearPassword(ctx, u.ID); err != nil {
		http.Redirect(w, r, "/profile?flash=Failed+to+remove+password", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/profile?flash=Password+removed", http.StatusFound)
}

