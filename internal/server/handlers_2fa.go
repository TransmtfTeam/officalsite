package server

import (
	"context"
	"net/http"
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
		h.renderError(w, r, http.StatusInternalServerError, "Internal Server Error", err.Error())
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

	d := h.pageData(r, "Two-Factor Authentication")
	d.Data = map[string]any{
		"Email":      u.Email,
		"HasTOTP":    u.TOTPEnabled && u.TOTPSecret != "",
		"HasPasskey": h.st.CountPasskeysByUserID(r.Context(), u.ID) > 0,
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
		d := h.pageData(r, "Two-Factor Authentication")
		d.IsError = true
		d.Flash = "Invalid verification code, please try again"
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
	sid, err := h.st.CreateSession(r.Context(), u.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "Session creation failed", err.Error())
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
		h.renderProfileWith2FA(w, r, "2FA is already enabled", true)
		return
	}
	currentPass := r.FormValue("current_password")
	if !h.st.VerifyPassword(u, currentPass) {
		h.renderProfileWith2FA(w, r, "Current password is incorrect", true)
		return
	}

	secret, err := newTOTPSecret()
	if err != nil {
		h.renderProfileWith2FA(w, r, "Unable to generate 2FA secret", true)
		return
	}
	if err := h.st.SavePendingTOTPSecret(r.Context(), u.ID, secret); err != nil {
		h.renderProfileWith2FA(w, r, "Failed to save 2FA configuration", true)
		return
	}
	h.renderProfileWith2FA(w, r, "Use your authenticator app to scan the key and enter a verification code to enable 2FA", false)
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
		h.renderError(w, r, http.StatusInternalServerError, "User read failed", err.Error())
		return
	}
	if u.TOTPPendingSecret == "" {
		h.renderProfileWith2FA(w, r, "No pending 2FA configuration to enable", true)
		return
	}

	code := r.FormValue("totp_code")
	if !verifyTOTP(u.TOTPPendingSecret, code, time.Now()) {
		h.renderProfileWith2FA(w, r, "Invalid verification code, please try again", true)
		return
	}
	if err := h.st.EnableTOTP(r.Context(), u.ID); err != nil {
		h.renderProfileWith2FA(w, r, "Failed to enable 2FA", true)
		return
	}
	h.renderProfileWith2FA(w, r, "2FA enabled", false)
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
		h.renderError(w, r, http.StatusInternalServerError, "User read failed", err.Error())
		return
	}
	if !u.TOTPEnabled || u.TOTPSecret == "" {
		h.renderProfileWith2FA(w, r, "2FA is not enabled", true)
		return
	}
	if !h.st.VerifyPassword(u, r.FormValue("current_password")) {
		h.renderProfileWith2FA(w, r, "Current password is incorrect", true)
		return
	}
	if !verifyTOTP(u.TOTPSecret, r.FormValue("totp_code"), time.Now()) {
		h.renderProfileWith2FA(w, r, "Invalid verification code", true)
		return
	}
	if err := h.st.DisableTOTP(r.Context(), u.ID); err != nil {
		h.renderProfileWith2FA(w, r, "Failed to disable 2FA", true)
		return
	}
	h.renderProfileWith2FA(w, r, "2FA disabled", false)
}

func (h *Handler) renderProfileWith2FA(w http.ResponseWriter, r *http.Request, flash string, isErr bool) {
	u, err := h.st.GetUserByID(r.Context(), h.currentUser(r).ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "User read failed", err.Error())
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), ctxUser, u))
	d := h.pageData(r, "Profile")
	d.Flash = flash
	d.IsError = isErr

	ctx := r.Context()
	data := map[string]any{"Passkeys": nil}
	passkeys, _ := h.st.GetPasskeyCredentialsByUserID(ctx, u.ID)
	data["Passkeys"] = passkeys
	if u.TOTPPendingSecret != "" {
		siteName := orDefault(h.st.GetSetting(ctx, "site_name"), "Team TransMTF")
		data["PendingSecret"] = u.TOTPPendingSecret
		data["PendingURI"] = buildTOTPUri(siteName, u.Email, u.TOTPPendingSecret)
	}
	d.Data = data
	h.render(w, "profile", d)
}
