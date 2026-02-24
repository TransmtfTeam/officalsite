package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"transmtf.com/oidc/internal/store"
)


type webAuthnUser struct {
	user  *store.User
	creds []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte                        { return []byte(u.user.ID) }
func (u *webAuthnUser) WebAuthnName() string                      { return u.user.Email }
func (u *webAuthnUser) WebAuthnDisplayName() string               { return u.user.DisplayName }
func (u *webAuthnUser) WebAuthnIcon() string                      { return "" }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// buildWebAuthnUser loads a user's passkey credentials and wraps them.
func (h *Handler) buildWebAuthnUser(ctx context.Context, u *store.User) (*webAuthnUser, error) {
	dbCreds, err := h.st.GetPasskeyCredentialsByUserID(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	var creds []webauthn.Credential
	for _, dc := range dbCreds {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(dc.Credential), &c); err != nil {
			continue
		}
		creds = append(creds, c)
	}
	return &webAuthnUser{user: u, creds: creds}, nil
}

// newWebAuthn creates a configured WebAuthn instance.
func (h *Handler) newWebAuthn(ctx context.Context) (*webauthn.WebAuthn, error) {
	issuerURL, err := url.Parse(h.cfg.Issuer)
	if err != nil {
		return nil, err
	}
	siteName := h.st.GetSetting(ctx, "site_name")
	if siteName == "" {
		siteName = "Team TransMTF"
	}
	rpID := issuerURL.Hostname()
	return webauthn.New(&webauthn.Config{
		RPDisplayName: siteName,
		RPID:          rpID,
		RPOrigins:     []string{h.cfg.Issuer},
	})
}


func (h *Handler) PasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	u := h.currentUser(r)
	if u == nil {
		jsonResp(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	ctx := r.Context()
	wa, err := h.newWebAuthn(ctx)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "webauthn init failed"})
		return
	}

	wau, err := h.buildWebAuthnUser(ctx, u)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "failed to load credentials"})
		return
	}

	options, session, err := wa.BeginRegistration(wau,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	sessionData, err := json.Marshal(session)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "session marshal failed"})
		return
	}

	sessID := uuid.New().String()
	if err := h.st.CreateWebAuthnSession(ctx, sessID, string(sessionData)); err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "session store failed"})
		return
	}

	w.Header().Set("X-WebAuthn-Session", sessID)
	jsonResp(w, http.StatusOK, options)
}

func (h *Handler) PasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	u := h.currentUser(r)
	if u == nil {
		jsonResp(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	ctx := r.Context()
	sessID := r.Header.Get("X-WebAuthn-Session")
	if sessID == "" {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "missing session ID"})
		return
	}

	sessionData, err := h.st.GetWebAuthnSession(ctx, sessID)
	if err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired session"})
		return
	}
	defer h.st.DeleteWebAuthnSession(ctx, sessID)

	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "session unmarshal failed"})
		return
	}

	wa, err := h.newWebAuthn(ctx)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "webauthn init failed"})
		return
	}

	wau, err := h.buildWebAuthnUser(ctx, u)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "failed to load credentials"})
		return
	}

	credential, err := wa.FinishRegistration(wau, session, r)
	if err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "registration failed: " + err.Error()})
		return
	}

	credData, err := json.Marshal(credential)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "credential marshal failed"})
		return
	}

	credID := base64.RawURLEncoding.EncodeToString(credential.ID)
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "Passkey"
	}

	if err := h.st.CreatePasskeyCredential(ctx, u.ID, credID, string(credData), name); err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "failed to save credential"})
		return
	}
	if u.RequirePasswordChange {
		if err := h.st.SetRequirePasswordChange(ctx, u.ID, false); err != nil {
			jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "failed to update account security state"})
			return
		}
	}

	jsonResp(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (h *Handler) PasskeyDeleteCredential(w http.ResponseWriter, r *http.Request) {
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
	id := r.PathValue("id")
	ctx := r.Context()
	creds, err := h.st.GetPasskeyCredentialsByUserID(ctx, u.ID)
	if err != nil {
        http.Redirect(w, r, "/profile?flash=Delete+failed", http.StatusFound)
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
        http.Redirect(w, r, "/profile?flash=Passkey+not+found", http.StatusFound)
		return
	}
	hasPassword := store.HasPassword(u)
	hasTOTP := u.TOTPEnabled && u.TOTPSecret != ""
	passkeyCount := len(creds)

	// Passwordless accounts must keep at least one passkey.
	if !hasPassword && passkeyCount <= 1 {
		http.Redirect(w, r, "/profile?flash=Cannot+delete+the+last+passkey+for+a+passwordless+account", http.StatusFound)
		return
	}

	currentPass := strings.TrimSpace(r.FormValue("current_password"))
	totpCode := strings.TrimSpace(r.FormValue("totp_code"))
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
			http.Redirect(w, r, "/profile?flash=Please+provide+a+valid+password+or+TOTP+code", http.StatusFound)
			return
		}
	} else {
		// No password: require an alternate verification method (TOTP) before deletion.
		if !hasTOTP {
			http.Redirect(w, r, "/profile?flash=Enable+TOTP+or+set+a+password+before+deleting+passkeys", http.StatusFound)
			return
		}
		if !totpOK {
			http.Redirect(w, r, "/profile?flash=Valid+TOTP+code+is+required", http.StatusFound)
			return
		}
	}

	if err := h.st.DeletePasskeyCredential(ctx, id); err != nil {
        http.Redirect(w, r, "/profile?flash=Delete+failed", http.StatusFound)
		return
	}
    http.Redirect(w, r, "/profile?flash=Passkey+deleted", http.StatusFound)
}


func (h *Handler) PasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	chID := h.twoFAChallengeFromRequest(r)
	if chID == "" {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "no 2FA challenge"})
		return
	}
	ctx := r.Context()
	ch, err := h.st.GetLogin2FAChallenge(ctx, chID)
	if err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid challenge"})
		return
	}
	u, err := h.st.GetUserByID(ctx, ch.UserID)
	if err != nil || !u.Active {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "user not found"})
		return
	}

	if h.st.CountPasskeysByUserID(ctx, u.ID) == 0 {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "no passkeys registered"})
		return
	}

	wa, err := h.newWebAuthn(ctx)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "webauthn init failed"})
		return
	}

	wau, err := h.buildWebAuthnUser(ctx, u)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "failed to load credentials"})
		return
	}

	options, session, err := wa.BeginLogin(wau)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	sessionData, err := json.Marshal(session)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "session marshal failed"})
		return
	}

	sessID := "pk_" + uuid.New().String()
	if err := h.st.CreateWebAuthnSession(ctx, sessID, string(sessionData)); err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "session store failed"})
		return
	}

	w.Header().Set("X-WebAuthn-Session", sessID)
	jsonResp(w, http.StatusOK, options)
}

func (h *Handler) PasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	chID := h.twoFAChallengeFromRequest(r)
	if chID == "" {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "no 2FA challenge"})
		return
	}

	ctx := r.Context()
	sessID := r.Header.Get("X-WebAuthn-Session")
	if sessID == "" {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "missing session ID"})
		return
	}

	sessionData, err := h.st.GetWebAuthnSession(ctx, sessID)
	if err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired webauthn session"})
		return
	}
	defer h.st.DeleteWebAuthnSession(ctx, sessID)

	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "session unmarshal failed"})
		return
	}

	ch, err := h.st.GetLogin2FAChallenge(ctx, chID)
	if err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid 2FA challenge"})
		return
	}

	u, err := h.st.GetUserByID(ctx, ch.UserID)
	if err != nil || !u.Active {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "user not found"})
		return
	}

	wa, err := h.newWebAuthn(ctx)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "webauthn init failed"})
		return
	}

	wau, err := h.buildWebAuthnUser(ctx, u)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "failed to load credentials"})
		return
	}

	credential, err := wa.FinishLogin(wau, session, r)
	if err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "passkey verification failed: " + err.Error()})
		return
	}

	// Update sign count in DB
	if credential != nil {
		updatedCred, merr := json.Marshal(credential)
		if merr == nil {
			credID := base64.RawURLEncoding.EncodeToString(credential.ID)
			_ = h.st.UpdatePasskeyCredential(ctx, credID, string(updatedCred))
		}
	}

	// Consume 2FA challenge and create session
	if _, err := h.st.ConsumeLogin2FAChallenge(ctx, chID); err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "failed to consume challenge"})
		return
	}
	h.clear2FAChallengeCookie(w)

	if u.RequirePasswordChange {
		sid, _ := h.st.CreateSession(ctx, u.ID)
		h.setSessionCookie(w, sid)
		jsonResp(w, http.StatusOK, map[string]string{"redirect": "/profile/change-password"})
		return
	}

	sid, err := h.st.CreateSession(ctx, u.ID)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "failed to create session"})
		return
	}
	h.setSessionCookie(w, sid)

	redirect := safeNextPath(ch.Redirect, "/profile")
	jsonResp(w, http.StatusOK, map[string]string{"redirect": redirect})
}


func (h *Handler) AdminDeletePasskey(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	userID := r.PathValue("id")
	pkID := r.PathValue("pkid")
	ctx := r.Context()

	targetUser, err := h.st.GetUserByID(ctx, userID)
	if err != nil {
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=User+not+found", http.StatusFound)
		return
	}
	cur := h.currentUser(r)
	if targetUser.IsAdmin() && !h.isSystemAdminUser(cur) {
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=Cannot+modify+admin+account", http.StatusFound)
		return
	}

	creds, err := h.st.GetPasskeyCredentialsByUserID(ctx, userID)
	if err != nil {
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=Delete+failed", http.StatusFound)
		return
	}
	for _, c := range creds {
		if c.ID == pkID {
			if dbErr := h.st.DeletePasskeyCredential(ctx, pkID); dbErr != nil {
				http.Redirect(w, r, "/admin/users/"+userID+"?flash=Delete+failed", http.StatusFound)
				return
			}
			break
		}
	}
	http.Redirect(w, r, "/admin/users/"+userID, http.StatusFound)
}

// PasskeyPrimaryLoginBegin starts a discoverable passkey login (no 2FA challenge required).
// GET /login/passkey/begin
func (h *Handler) PasskeyPrimaryLoginBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wa, err := h.newWebAuthn(ctx)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "webauthn init failed"})
		return
	}

	options, session, err := wa.BeginDiscoverableLogin()
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	sessionData, err := json.Marshal(session)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "session marshal failed"})
		return
	}

	sessID := "pkprimary_" + uuid.New().String()
	if err := h.st.CreateWebAuthnSession(ctx, sessID, string(sessionData)); err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "session store failed"})
		return
	}

	w.Header().Set("X-WebAuthn-Session", sessID)
	jsonResp(w, http.StatusOK, options)
}

// PasskeyPrimaryLoginFinish completes a discoverable passkey login.
// POST /login/passkey/finish
func (h *Handler) PasskeyPrimaryLoginFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sessID := r.Header.Get("X-WebAuthn-Session")
	if sessID == "" {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "missing session ID"})
		return
	}

	sessionData, err := h.st.GetWebAuthnSession(ctx, sessID)
	if err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired session"})
		return
	}
	defer h.st.DeleteWebAuthnSession(ctx, sessID)

	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "session unmarshal failed"})
		return
	}

	wa, err := h.newWebAuthn(ctx)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "webauthn init failed"})
		return
	}

	var resolvedUser *store.User
	var resolvedWAU *webAuthnUser

	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		credID := base64.RawURLEncoding.EncodeToString(rawID)
		pkCred, err := h.st.GetPasskeyCredentialByCredentialID(ctx, credID)
		if err != nil {
			return nil, err
		}
		u, err := h.st.GetUserByID(ctx, pkCred.UserID)
		if err != nil {
			return nil, err
		}
		resolvedUser = u
		wau, err := h.buildWebAuthnUser(ctx, u)
		if err != nil {
			return nil, err
		}
		resolvedWAU = wau
		return wau, nil
	}

	credential, err := wa.FinishDiscoverableLogin(handler, session, r)
	if err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "passkey verification failed: " + err.Error()})
		return
	}

	if resolvedUser == nil || !resolvedUser.Active {
		jsonResp(w, http.StatusForbidden, map[string]string{"error": "account not found or disabled"})
		return
	}
	_ = resolvedWAU

	// Update sign count in DB.
	if credential != nil {
		if updatedCred, merr := json.Marshal(credential); merr == nil {
			credID := base64.RawURLEncoding.EncodeToString(credential.ID)
			_ = h.st.UpdatePasskeyCredential(ctx, credID, string(updatedCred))
		}
	}

	if resolvedUser.RequirePasswordChange {
		sid, _ := h.st.CreateSession(ctx, resolvedUser.ID)
		h.setSessionCookie(w, sid)
		jsonResp(w, http.StatusOK, map[string]string{"redirect": "/profile/change-password"})
		return
	}

	sid, err := h.st.CreateSession(ctx, resolvedUser.ID)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "failed to create session"})
		return
	}
	h.setSessionCookie(w, sid)
	jsonResp(w, http.StatusOK, map[string]string{"redirect": "/profile"})
}
