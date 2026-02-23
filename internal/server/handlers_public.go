package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

func (h *Handler) Home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		h.renderError(w, r, http.StatusNotFound, "Not Found", r.URL.Path)
		return
	}
	projects, _ := h.st.ListProjects(r.Context())
	d := h.pageData(r, "MTF - Team TransMTF")
	d.Data = projects
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
		d.Flash = "Invalid email or password"
		d.IsError = true
		d.Data = map[string]any{"Next": next, "Providers": providers}
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
	u, err := h.st.CreateUser(ctx, email, pass, name, "user")
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			fail("Email already registered")
		} else {
			fail("Registration failed: " + err.Error())
		}
		return
	}

	sid, err := h.st.CreateSession(ctx, u.ID)
	if err == nil {
		h.setSessionCookie(w, sid)
	}
	go h.sendWelcomeEmail(context.Background(), u.Email, u.DisplayName)
	http.Redirect(w, r, "/profile", http.StatusFound)
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
	if err := h.st.UpdateUser(ctx, u.ID, name, u.Role, u.Active); err != nil {
		fail("Save failed: " + err.Error())
		return
	}
	if avatar != "" {
		_ = h.st.UpdateUserAvatar(ctx, u.ID, avatar)
	}

	if newPass != "" {
		if len(newPass) < 8 {
			fail("New password must be at least 8 characters")
			return
		}
		if newPass != confirm {
			fail("Passwords do not match")
			return
		}
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
