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

func (u *webAuthnUser) WebAuthnID() []byte                         { return []byte(u.user.ID) }
func (u *webAuthnUser) WebAuthnName() string                       { return u.user.Email }
func (u *webAuthnUser) WebAuthnDisplayName() string                { return u.user.DisplayName }
func (u *webAuthnUser) WebAuthnIcon() string                       { return "" }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// buildWebAuthnUser 读取用户的通行密钥凭据并进行封装。
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
		siteName = "团队站点"
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
		jsonResp(w, http.StatusUnauthorized, map[string]string{"error": "未授权"})
		return
	}

	ctx := r.Context()
	wa, err := h.newWebAuthn(ctx)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "通行密钥组件初始化失败"})
		return
	}

	wau, err := h.buildWebAuthnUser(ctx, u)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "加载通行密钥凭据失败"})
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
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "会话序列化失败"})
		return
	}

	sessID := uuid.New().String()
	if err := h.st.CreateWebAuthnSession(ctx, sessID, string(sessionData)); err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "会话存储失败"})
		return
	}

	w.Header().Set("X-WebAuthn-Session", sessID)
	jsonResp(w, http.StatusOK, options)
}

func (h *Handler) PasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	u := h.currentUser(r)
	if u == nil {
		jsonResp(w, http.StatusUnauthorized, map[string]string{"error": "未授权"})
		return
	}

	ctx := r.Context()
	sessID := r.Header.Get("X-WebAuthn-Session")
	if sessID == "" {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "缺少会话标识"})
		return
	}

	sessionData, err := h.st.GetWebAuthnSession(ctx, sessID)
	if err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "会话无效或已过期"})
		return
	}
	defer h.st.DeleteWebAuthnSession(ctx, sessID)

	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "会话反序列化失败"})
		return
	}

	wa, err := h.newWebAuthn(ctx)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "通行密钥组件初始化失败"})
		return
	}

	wau, err := h.buildWebAuthnUser(ctx, u)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "加载通行密钥凭据失败"})
		return
	}

	credential, err := wa.FinishRegistration(wau, session, r)
	if err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "注册失败：" + err.Error()})
		return
	}

	credData, err := json.Marshal(credential)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "凭据序列化失败"})
		return
	}

	credID := base64.RawURLEncoding.EncodeToString(credential.ID)
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "通行密钥"
	}

	if err := h.st.CreatePasskeyCredential(ctx, u.ID, credID, string(credData), name); err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "保存凭据失败"})
		return
	}
	if u.RequirePasswordChange {
		if err := h.st.SetRequirePasswordChange(ctx, u.ID, false); err != nil {
			jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "更新账户安全状态失败"})
			return
		}
	}

	jsonResp(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (h *Handler) PasskeyDeleteCredential(w http.ResponseWriter, r *http.Request) {
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
	id := r.PathValue("id")
	ctx := r.Context()
	creds, err := h.st.GetPasskeyCredentialsByUserID(ctx, u.ID)
	if err != nil {
		http.Redirect(w, r, "/profile?flash=删除失败", http.StatusFound)
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
		http.Redirect(w, r, "/profile?flash=通行密钥不存在", http.StatusFound)
		return
	}
	hasPassword := store.HasPassword(u)
	hasTOTP := u.TOTPEnabled && u.TOTPSecret != ""
	passkeyCount := len(creds)

	// 无密码账户必须至少保留一个通行密钥。
	if !hasPassword && passkeyCount <= 1 {
		http.Redirect(w, r, "/profile?flash=无密码账户不能删除最后一个通行密钥", http.StatusFound)
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
			http.Redirect(w, r, "/profile?flash=请提供有效的密码或动态口令验证码", http.StatusFound)
			return
		}
	} else {
		// 无密码时：删除前必须通过替代验证方式（动态口令）进行校验。
		if !hasTOTP {
			http.Redirect(w, r, "/profile?flash=删除通行密钥前请先启用动态口令或设置密码", http.StatusFound)
			return
		}
		if !totpOK {
			http.Redirect(w, r, "/profile?flash=需要有效的动态口令验证码", http.StatusFound)
			return
		}
	}

	if err := h.st.DeletePasskeyCredential(ctx, id); err != nil {
		http.Redirect(w, r, "/profile?flash=删除失败", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/profile?flash=通行密钥已删除", http.StatusFound)
}

func (h *Handler) PasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	chID := h.twoFAChallengeFromRequest(r)
	if chID == "" {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "没有双重验证挑战"})
		return
	}
	ctx := r.Context()
	ch, err := h.st.GetLogin2FAChallenge(ctx, chID)
	if err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "挑战无效"})
		return
	}
	u, err := h.st.GetUserByID(ctx, ch.UserID)
	if err != nil || !u.Active {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "用户不存在"})
		return
	}

	if h.st.CountPasskeysByUserID(ctx, u.ID) == 0 {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "未注册通行密钥"})
		return
	}

	wa, err := h.newWebAuthn(ctx)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "通行密钥组件初始化失败"})
		return
	}

	wau, err := h.buildWebAuthnUser(ctx, u)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "加载通行密钥凭据失败"})
		return
	}

	options, session, err := wa.BeginLogin(wau)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	sessionData, err := json.Marshal(session)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "会话序列化失败"})
		return
	}

	sessID := "pk_" + uuid.New().String()
	if err := h.st.CreateWebAuthnSession(ctx, sessID, string(sessionData)); err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "会话存储失败"})
		return
	}

	w.Header().Set("X-WebAuthn-Session", sessID)
	jsonResp(w, http.StatusOK, options)
}

func (h *Handler) PasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	chID := h.twoFAChallengeFromRequest(r)
	if chID == "" {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "没有双重验证挑战"})
		return
	}

	ctx := r.Context()
	sessID := r.Header.Get("X-WebAuthn-Session")
	if sessID == "" {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "缺少会话标识"})
		return
	}

	sessionData, err := h.st.GetWebAuthnSession(ctx, sessID)
	if err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "通行密钥会话无效或已过期"})
		return
	}
	defer h.st.DeleteWebAuthnSession(ctx, sessID)

	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "会话反序列化失败"})
		return
	}

	ch, err := h.st.GetLogin2FAChallenge(ctx, chID)
	if err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "双重验证挑战无效"})
		return
	}

	u, err := h.st.GetUserByID(ctx, ch.UserID)
	if err != nil || !u.Active {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "用户不存在"})
		return
	}

	wa, err := h.newWebAuthn(ctx)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "通行密钥组件初始化失败"})
		return
	}

	wau, err := h.buildWebAuthnUser(ctx, u)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "加载通行密钥凭据失败"})
		return
	}

	credential, err := wa.FinishLogin(wau, session, r)
	if err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "通行密钥验证失败：" + err.Error()})
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
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "消耗挑战失败"})
		return
	}
	h.clear2FAChallengeCookie(w)

	redirect := safeNextPath(ch.Redirect, "/profile")

	if u.RequirePasswordChange {
		sid, _ := h.st.CreateSession(ctx, u.ID)
		h.setSessionCookie(w, sid)
		target := "/profile/change-password"
		if redirect != "" && redirect != "/profile" {
			target += "?next=" + url.QueryEscape(redirect)
		}
		jsonResp(w, http.StatusOK, map[string]string{"redirect": target})
		return
	}

	sid, err := h.st.CreateSession(ctx, u.ID)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "创建会话失败"})
		return
	}
	h.setSessionCookie(w, sid)
	jsonResp(w, http.StatusOK, map[string]string{"redirect": redirect})
}

func (h *Handler) AdminDeletePasskey(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
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
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=用户不存在", http.StatusFound)
		return
	}
	cur := h.currentUser(r)
	if targetUser.IsAdmin() && !h.isSystemAdminUser(cur) {
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=不能修改管理员账户", http.StatusFound)
		return
	}

	creds, err := h.st.GetPasskeyCredentialsByUserID(ctx, userID)
	if err != nil {
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=删除失败", http.StatusFound)
		return
	}
	for _, c := range creds {
		if c.ID == pkID {
			if dbErr := h.st.DeletePasskeyCredential(ctx, pkID); dbErr != nil {
				http.Redirect(w, r, "/admin/users/"+userID+"?flash=删除失败", http.StatusFound)
				return
			}
			break
		}
	}
	http.Redirect(w, r, "/admin/users/"+userID, http.StatusFound)
}

// PasskeyPrimaryLoginBegin 启动可发现凭据的通行密钥登录（无需双重验证挑战）。
// GET /login/passkey/begin
func (h *Handler) PasskeyPrimaryLoginBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wa, err := h.newWebAuthn(ctx)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "通行密钥组件初始化失败"})
		return
	}

	options, session, err := wa.BeginDiscoverableLogin()
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	sessionData, err := json.Marshal(session)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "会话序列化失败"})
		return
	}

	sessID := "pkprimary_" + uuid.New().String()
	if err := h.st.CreateWebAuthnSession(ctx, sessID, string(sessionData)); err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "会话存储失败"})
		return
	}

	w.Header().Set("X-WebAuthn-Session", sessID)
	jsonResp(w, http.StatusOK, options)
}

// PasskeyPrimaryLoginFinish 完成可发现凭据的通行密钥登录。
// POST /login/passkey/finish
func (h *Handler) PasskeyPrimaryLoginFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sessID := r.Header.Get("X-WebAuthn-Session")
	if sessID == "" {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "缺少会话标识"})
		return
	}

	sessionData, err := h.st.GetWebAuthnSession(ctx, sessID)
	if err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "会话无效或已过期"})
		return
	}
	defer h.st.DeleteWebAuthnSession(ctx, sessID)

	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "会话反序列化失败"})
		return
	}

	wa, err := h.newWebAuthn(ctx)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "通行密钥组件初始化失败"})
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
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "通行密钥验证失败：" + err.Error()})
		return
	}

	if resolvedUser == nil || !resolvedUser.Active {
		jsonResp(w, http.StatusForbidden, map[string]string{"error": "账户不存在或已停用"})
		return
	}
	_ = resolvedWAU

	redirectNext := safeNextPath(r.URL.Query().Get("next"), "/profile")
	oidcChallenge := strings.TrimSpace(r.URL.Query().Get("oidc_challenge"))
	if oidcChallenge != "" {
		challengeNext, linkErr := h.consumeOIDCLoginChallengeAndLink(ctx, resolvedUser, oidcChallenge)
		if linkErr != nil {
			jsonResp(w, http.StatusBadRequest, map[string]string{"error": linkErr.Error()})
			return
		}
		if challengeNext != "" {
			redirectNext = challengeNext
		}
	}

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
		target := "/profile/change-password"
		if redirectNext != "" && redirectNext != "/profile" {
			target += "?next=" + url.QueryEscape(redirectNext)
		}
		jsonResp(w, http.StatusOK, map[string]string{"redirect": target})
		return
	}

	sid, err := h.st.CreateSession(ctx, resolvedUser.ID)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "创建会话失败"})
		return
	}
	h.setSessionCookie(w, sid)
	jsonResp(w, http.StatusOK, map[string]string{"redirect": redirectNext})
}
