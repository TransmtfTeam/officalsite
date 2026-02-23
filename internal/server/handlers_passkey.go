package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"

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
