package server

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"transmtf.com/oidc/internal/store"
)

func (h *Handler) Discovery(w http.ResponseWriter, r *http.Request) {
	iss := h.cfg.Issuer
	jsonResp(w, 200, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/oauth2/authorize",
		"token_endpoint":                        iss + "/oauth2/token",
		"userinfo_endpoint":                     iss + "/oauth2/userinfo",
		"jwks_uri":                              iss + "/.well-known/jwks.json",
		"introspection_endpoint":                iss + "/oauth2/introspect",
		"revocation_endpoint":                   iss + "/oauth2/revoke",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "email", "name", "picture", "role"},
	})
}

func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	jsonResp(w, 200, h.keys.JWKSet())
}

type authRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ar := authRequest{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		ResponseType:        q.Get("response_type"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
	}

	client, err := h.st.GetClientByClientID(r.Context(), ar.ClientID)
	if err != nil {
		oidcError(w, 400, "invalid_client", "未知应用标识")
		return
	}
	// Validate redirect_uri first - before any redirect-based error response
	if !validRedirectURI(client.RedirectURIs, ar.RedirectURI) {
		oidcError(w, 400, "invalid_request", "回调地址不匹配")
		return
	}
	if ar.ResponseType != "code" {
		h.authRedirectError(w, r, ar.RedirectURI, ar.State, "unsupported_response_type", "仅支持授权码模式")
		return
	}
	reqScopes := normalizeScopes(scopeList(ar.Scope))
	if len(reqScopes) == 0 {
		h.authRedirectError(w, r, ar.RedirectURI, ar.State, "invalid_scope", "至少需要一个权限范围")
		return
	}
	if !scopesSubset(reqScopes, client.Scopes) {
		h.authRedirectError(w, r, ar.RedirectURI, ar.State, "invalid_scope", "请求的权限范围不在应用允许列表中")
		return
	}
	ar.Scope = strings.Join(reqScopes, " ")
	if ar.CodeChallengeMethod == "" && ar.CodeChallenge != "" {
		ar.CodeChallengeMethod = "plain"
	}
	if ar.CodeChallenge != "" && ar.CodeChallengeMethod != "S256" && ar.CodeChallengeMethod != "plain" {
		h.authRedirectError(w, r, ar.RedirectURI, ar.State, "invalid_request", "不支持的挑战校验方式")
		return
	}
	if ar.CodeChallenge == "" && ar.CodeChallengeMethod != "" {
		h.authRedirectError(w, r, ar.RedirectURI, ar.State, "invalid_request", "设置挑战校验方式时必须提供挑战值")
		return
	}

	// Check client access policy (base role policy OR group membership).
	u := h.currentUser(r)
	if !h.st.UserCanAccessClient(r.Context(), u, client.BaseAccess, client.AllowedGroups) {
		d := h.pageData(r, "访问受限")
		d.Flash = "您没有访问此应用的权限，请联系管理员。"
		d.IsError = true
		h.render(w, "error", d)
		return
	}

	// Build display scopes: remove "role" if "profile" is already requested.
	displayScopes := filterRedundantScopes(reqScopes)

	d := h.pageData(r, "授权确认")
	d.Data = map[string]any{
		"Client":  client,
		"Request": ar,
		"Scopes":  displayScopes,
	}
	h.render(w, "consent", d)
}

// filterRedundantScopes removes scope items that are already implied by other scopes.
// Specifically, "role" is implied by "profile" (profile already exposes the role claim).
func filterRedundantScopes(scopes []string) []string {
	hasProfile := false
	for _, s := range scopes {
		if s == "profile" {
			hasProfile = true
			break
		}
	}
	if !hasProfile {
		return scopes
	}
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if s == "role" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func (h *Handler) AuthorizeConfirm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", 400)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	action := r.FormValue("action")
	if action != "allow" && action != "deny" {
		oidcError(w, 400, "invalid_request", "授权操作无效")
		return
	}
	ar := authRequest{
		ClientID:            r.FormValue("client_id"),
		RedirectURI:         r.FormValue("redirect_uri"),
		Scope:               r.FormValue("scope"),
		State:               r.FormValue("state"),
		Nonce:               r.FormValue("nonce"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
	}

	client, err := h.st.GetClientByClientID(r.Context(), ar.ClientID)
	if err != nil || !validRedirectURI(client.RedirectURIs, ar.RedirectURI) {
		oidcError(w, 400, "invalid_client", "应用标识或回调地址无效")
		return
	}
	reqScopes := normalizeScopes(scopeList(ar.Scope))
	if len(reqScopes) == 0 {
		oidcError(w, 400, "invalid_scope", "至少需要一个权限范围")
		return
	}
	if !scopesSubset(reqScopes, client.Scopes) {
		oidcError(w, 400, "invalid_scope", "请求的权限范围不在应用允许列表中")
		return
	}
	if ar.CodeChallengeMethod == "" && ar.CodeChallenge != "" {
		ar.CodeChallengeMethod = "plain"
	}
	if ar.CodeChallenge != "" && ar.CodeChallengeMethod != "S256" && ar.CodeChallengeMethod != "plain" {
		oidcError(w, 400, "invalid_request", "不支持的挑战校验方式")
		return
	}
	if ar.CodeChallenge == "" && ar.CodeChallengeMethod != "" {
		oidcError(w, 400, "invalid_request", "设置挑战校验方式时必须提供挑战值")
		return
	}
	if action == "deny" {
		h.authRedirectError(w, r, ar.RedirectURI, ar.State, "access_denied", "用户拒绝授权")
		return
	}

	u := h.currentUser(r)
	// Re-validate access policy on POST (don't trust only the GET check).
	if !h.st.UserCanAccessClient(r.Context(), u, client.BaseAccess, client.AllowedGroups) {
		oidcError(w, 403, "access_denied", "当前账户不满足应用访问策略")
		return
	}

	code := store.RandomHex(24)
	scopes := reqScopes

	if err := h.st.CreateAuthCode(r.Context(), code, ar.ClientID, u.ID, ar.RedirectURI, scopes,
		ar.CodeChallenge, ar.CodeChallengeMethod, ar.Nonce); err != nil {
		h.authRedirectError(w, r, ar.RedirectURI, ar.State, "server_error", err.Error())
		return
	}

	redir, err := appendRedirectParams(ar.RedirectURI, map[string]string{
		"code":  code,
		"state": ar.State,
	})
	if err != nil {
		oidcError(w, 400, "invalid_request", "回调地址无效")
		return
	}
	http.Redirect(w, r, redir, http.StatusFound)
}

func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oidcError(w, 400, "invalid_request", "无法解析请求参数")
		return
	}

	clientID, clientSecret := extractClientCreds(r)
	if clientID == "" {
		oidcError(w, 401, "invalid_client", "缺少应用凭据")
		return
	}

	client, err := h.st.GetClientByClientID(r.Context(), clientID)
	if err != nil || !h.st.VerifyClientSecret(client, clientSecret) {
		oidcError(w, 401, "invalid_client", "应用身份验证失败")
		return
	}

	grantType := r.FormValue("grant_type")
	switch grantType {
	case "authorization_code":
		h.tokenAuthCode(w, r, client)
	case "refresh_token":
		h.tokenRefresh(w, r, client)
	case "client_credentials":
		h.tokenClientCredentials(w, r, client)
	default:
		oidcError(w, 400, "unsupported_grant_type", "不支持的授权类型")
	}
}

func (h *Handler) tokenAuthCode(w http.ResponseWriter, r *http.Request, client *store.OAuthClient) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	verifier := r.FormValue("code_verifier")

	ac, err := h.st.ConsumeAuthCode(r.Context(), code)
	if err != nil {
		oidcError(w, 400, "invalid_grant", "授权码无效或已过期")
		return
	}
	if ac.ClientID != client.ClientID {
		oidcError(w, 400, "invalid_grant", "该授权码不属于当前应用")
		return
	}
	if ac.RedirectURI != redirectURI {
		oidcError(w, 400, "invalid_grant", "回调地址不匹配")
		return
	}
	if ac.Challenge != "" && verifier == "" {
		oidcError(w, 400, "invalid_grant", "缺少挑战校验值")
		return
	}
	if ac.Challenge != "" && !verifyPKCE(verifier, ac.Challenge, ac.Method) {
		oidcError(w, 400, "invalid_grant", "挑战校验失败")
		return
	}

	u, err := h.st.GetUserByID(r.Context(), ac.UserID)
	if err != nil {
		oidcError(w, 500, "server_error", "用户不存在")
		return
	}

	h.issueTokens(w, r, u, client.ClientID, ac.Scopes, ac.Nonce)
}

func (h *Handler) tokenRefresh(w http.ResponseWriter, r *http.Request, client *store.OAuthClient) {
	raw := r.FormValue("refresh_token")
	rt, err := h.st.GetRefreshToken(r.Context(), raw)
	if err != nil {
		oidcError(w, 400, "invalid_grant", "刷新令牌无效或已过期")
		return
	}
	if rt.ClientID != client.ClientID {
		oidcError(w, 400, "invalid_grant", "刷新令牌不属于当前应用")
		return
	}

	h.st.RevokeRefreshToken(r.Context(), raw)

	u, err := h.st.GetUserByID(r.Context(), rt.UserID)
	if err != nil {
		oidcError(w, 500, "server_error", "用户不存在")
		return
	}
	h.issueTokens(w, r, u, rt.ClientID, rt.Scopes, "")
}

// tokenClientCredentials issues an access token for machine-to-machine OAuth2.
// No user is associated; the subject is the client_id.
func (h *Handler) tokenClientCredentials(w http.ResponseWriter, r *http.Request, client *store.OAuthClient) {
	scopeReq := normalizeScopes(strings.Fields(r.FormValue("scope")))
	// Default to the client's registered scopes if none requested
	if len(scopeReq) == 0 {
		scopeReq = client.Scopes
	}
	if !scopesSubset(scopeReq, client.Scopes) {
		oidcError(w, 400, "invalid_scope", "请求的权限范围不在应用允许列表中")
		return
	}
	// Remove openid - client_credentials cannot issue ID tokens (no user context)
	var scopes []string
	for _, s := range scopeReq {
		if s != "openid" {
			scopes = append(scopes, s)
		}
	}

	ctx := r.Context()
	// user_id is empty for client_credentials - no user is involved
	at, err := h.st.CreateAccessToken(ctx, "", client.ClientID, scopes)
	if err != nil {
		oidcError(w, 500, "server_error", "创建访问令牌失败")
		return
	}
	jsonResp(w, 200, map[string]any{
		"access_token": at,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        strings.Join(scopes, " "),
	})
}

func (h *Handler) issueTokens(w http.ResponseWriter, r *http.Request, u *store.User, clientID string, scopes []string, nonce string) {
	ctx := r.Context()
	at, err := h.st.CreateAccessToken(ctx, u.ID, clientID, scopes)
	if err != nil {
		oidcError(w, 500, "server_error", "创建访问令牌失败")
		return
	}
	rt, err := h.st.CreateRefreshToken(ctx, u.ID, clientID, scopes)
	if err != nil {
		oidcError(w, 500, "server_error", "创建刷新令牌失败")
		return
	}

	resp := map[string]any{
		"access_token":  at,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": rt,
		"scope":         strings.Join(scopes, " "),
	}

	// Only issue id_token when the openid scope was requested (OIDC).
	// Pure OAuth2 clients omitting openid still receive access + refresh tokens.
	if containsScope(scopes, "openid") {
		idTok, err := h.keys.SignIDToken(h.cfg.Issuer, u.ID, clientID, nonce, scopes, u)
		if err != nil {
			oidcError(w, 500, "server_error", "签发身份令牌失败")
			return
		}
		resp["id_token"] = idTok
	}

	jsonResp(w, 200, resp)
}

func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	raw := bearerToken(r)
	if raw == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="transmtf"`)
		oidcError(w, 401, "invalid_token", "缺少访问令牌")
		return
	}
	at, err := h.st.GetAccessToken(r.Context(), raw)
	if err != nil {
		oidcError(w, 401, "invalid_token", "访问令牌已过期或不存在")
		return
	}
	if !containsScope(at.Scopes, "openid") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="transmtf", error="insufficient_scope", scope="openid"`)
		oidcError(w, 403, "insufficient_scope", "需要核心登录权限")
		return
	}
	// client_credentials tokens have no user_id; return client subject only.
	if at.UserID == "" {
		jsonResp(w, 200, map[string]any{"sub": at.ClientID})
		return
	}
	u, err := h.st.GetUserByID(r.Context(), at.UserID)
	if err != nil {
		oidcError(w, 500, "server_error", "用户不存在")
		return
	}

	claims := map[string]any{"sub": u.ID}
	for _, sc := range at.Scopes {
		switch sc {
		case "email":
			claims["email"] = u.Email
			claims["email_verified"] = u.EmailVerified
		case "profile":
			claims["name"] = u.DisplayName
			claims["picture"] = u.AvatarURL
			claims["role"] = u.Role
		}
	}
	jsonResp(w, 200, claims)
}

func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oidcError(w, 400, "invalid_request", "无法解析请求参数")
		return
	}
	clientID, clientSecret := extractClientCreds(r)
	client, err := h.st.GetClientByClientID(r.Context(), clientID)
	if err != nil || !h.st.VerifyClientSecret(client, clientSecret) {
		oidcError(w, 401, "invalid_client", "应用身份验证失败")
		return
	}
	token := r.FormValue("token")
	tokenType := r.FormValue("token_type_hint")
	ctx := r.Context()
	if tokenType == "refresh_token" {
		if rt, rtErr := h.st.GetRefreshToken(ctx, token); rtErr == nil && rt.ClientID == client.ClientID {
			h.st.RevokeRefreshToken(ctx, token)
		}
	} else {
		if at, atErr := h.st.GetAccessToken(ctx, token); atErr == nil && at.ClientID == client.ClientID {
			h.st.RevokeAccessToken(ctx, token)
		}
		if rt, rtErr := h.st.GetRefreshToken(ctx, token); rtErr == nil && rt.ClientID == client.ClientID {
			h.st.RevokeRefreshToken(ctx, token)
		}
	}
	w.WriteHeader(200)
}

func (h *Handler) Introspect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oidcError(w, 400, "invalid_request", "无法解析请求参数")
		return
	}
	clientID, clientSecret := extractClientCreds(r)
	client, err := h.st.GetClientByClientID(r.Context(), clientID)
	if err != nil || !h.st.VerifyClientSecret(client, clientSecret) {
		oidcError(w, 401, "invalid_client", "应用身份验证失败")
		return
	}
	raw := r.FormValue("token")
	at, err := h.st.GetAccessToken(r.Context(), raw)
	if err != nil {
		jsonResp(w, 200, map[string]any{"active": false})
		return
	}
	if at.ClientID != client.ClientID {
		jsonResp(w, 200, map[string]any{"active": false})
		return
	}

	subject := at.UserID
	if subject == "" {
		subject = at.ClientID
	}
	u, _ := h.st.GetUserByID(r.Context(), at.UserID)
	resp := map[string]any{
		"active":     true,
		"sub":        subject,
		"client_id":  at.ClientID,
		"scope":      strings.Join(at.Scopes, " "),
		"exp":        at.ExpiresAt.Unix(),
		"token_type": "Bearer",
	}
	if u != nil {
		resp["email"] = u.Email
		resp["username"] = u.Email
	} else if at.UserID == "" {
		resp["username"] = at.ClientID
	}
	jsonResp(w, 200, resp)
}

func extractClientCreds(r *http.Request) (id, secret string) {
	// Basic auth first
	if u, p, ok := r.BasicAuth(); ok {
		return u, p
	}
	return r.FormValue("client_id"), r.FormValue("client_secret")
}

func validRedirectURI(allowed []string, uri string) bool {
	for _, a := range allowed {
		if a == uri {
			return true
		}
	}
	return false
}

func scopeList(scope string) []string {
	return normalizeScopes(strings.Fields(scope))
}

func verifyPKCE(verifier, challenge, method string) bool {
	if method == "S256" {
		h := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(h[:]) == challenge
	}
	if method == "plain" || method == "" {
		return verifier == challenge
	}
	return false
}

func (h *Handler) authRedirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	u, err := appendRedirectParams(redirectURI, map[string]string{
		"error":             code,
		"error_description": desc,
		"state":             state,
	})
	if err != nil {
		oidcError(w, 400, "invalid_request", "回调地址无效")
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}

func appendRedirectParams(raw string, params map[string]string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, v := range params {
		if v == "" {
			continue
		}
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func containsScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}
