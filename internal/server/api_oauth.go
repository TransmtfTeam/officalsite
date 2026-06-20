package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"transmtf.com/oidc/internal/store"
)

func registerOAuthAPIRoutes(mux *http.ServeMux, h *Handler) {
	// OAuth2 consent (SPA-driven). GET returns consent info or a redirect target;
	// POST records the decision and returns the client redirect location.
	mux.HandleFunc("GET /api/v1/oauth2/authorize", h.apiRequireLogin(h.APIOAuthAuthorizeInfo))
	mux.HandleFunc("POST /api/v1/oauth2/authorize", h.apiRequireLogin(h.requireAPICSRF(h.APIOAuthAuthorizeDecision)))
	// Public content.
	mux.HandleFunc("GET /api/v1/home", h.APIHome)
	mux.HandleFunc("GET /api/v1/tos", h.APITOS)
	mux.HandleFunc("GET /api/v1/privacy", h.APIPrivacy)
	// Profile external-identity bind (returns the provider auth URL to navigate to).
	mux.HandleFunc("POST /api/v1/profile/identities/{slug}/bind", h.apiRequireLogin(h.requireAPICSRF(h.APIProfileIdentityBind)))
}

// oauthScopeLabel mirrors the scopeLabel template function (main.go) so the
// consent screen shows the same human descriptions.
func oauthScopeLabel(s string) string {
	switch s {
	case "openid":
		return "确认您的身份"
	case "email":
		return "读取您的电子邮箱"
	case "profile":
		return "读取您的公开资料（显示名称、头像、角色）"
	case "role":
		return "读取您的角色"
	default:
		return s
	}
}

func oauthRedirectError(redirectURI, state, code, desc string) (string, error) {
	return appendRedirectParams(redirectURI, map[string]string{
		"error":             code,
		"error_description": desc,
		"state":             state,
	})
}

// APIOAuthAuthorizeInfo mirrors Authorize: validates the request and returns
// either consent details or a redirect target. Protocol errors (bad client /
// redirect_uri) are returned as apiErr so React shows an error WITHOUT
// navigating; redirectable OAuth errors are returned as {action:"redirect"}.
func (h *Handler) APIOAuthAuthorizeInfo(w http.ResponseWriter, r *http.Request) {
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
		apiErr(w, http.StatusBadRequest, "invalid_client", "未知应用标识")
		return
	}
	if !validRedirectURI(client.RedirectURIs, ar.RedirectURI) {
		apiErr(w, http.StatusBadRequest, "invalid_request", "回调地址不匹配")
		return
	}
	redirectErr := func(code, desc string) {
		loc, uerr := oauthRedirectError(ar.RedirectURI, ar.State, code, desc)
		if uerr != nil {
			apiErr(w, http.StatusBadRequest, "invalid_request", "回调地址无效")
			return
		}
		apiOK(w, http.StatusOK, map[string]any{"action": "redirect", "location": loc})
	}
	if ar.ResponseType != "code" {
		redirectErr("unsupported_response_type", "仅支持授权码模式")
		return
	}
	reqScopes := normalizeScopes(scopeList(ar.Scope))
	if len(reqScopes) == 0 {
		redirectErr("invalid_scope", "至少需要一个权限范围")
		return
	}
	if !scopesSubset(reqScopes, client.Scopes) {
		redirectErr("invalid_scope", "请求的权限范围不在应用允许列表中")
		return
	}
	ar.Scope = strings.Join(reqScopes, " ")
	if ar.CodeChallengeMethod == "" && ar.CodeChallenge != "" {
		ar.CodeChallengeMethod = "plain"
	}
	if ar.CodeChallenge != "" && ar.CodeChallengeMethod != "S256" && ar.CodeChallengeMethod != "plain" {
		redirectErr("invalid_request", "不支持的挑战校验方式")
		return
	}
	if ar.CodeChallenge == "" && ar.CodeChallengeMethod != "" {
		redirectErr("invalid_request", "设置挑战校验方式时必须提供挑战值")
		return
	}

	u := h.currentUser(r)
	if !h.st.UserCanAccessClient(r.Context(), u, client.BaseAccess, client.AllowedGroups) {
		apiErr(w, http.StatusForbidden, "access_denied", "您没有访问此应用的权限，请联系管理员。")
		return
	}

	displayScopes := filterRedundantScopes(reqScopes)
	scopeObjs := make([]map[string]string, 0, len(displayScopes))
	for _, s := range displayScopes {
		scopeObjs = append(scopeObjs, map[string]string{"key": s, "label": oauthScopeLabel(s)})
	}
	apiOK(w, http.StatusOK, map[string]any{
		"action": "consent",
		"client": map[string]any{
			"name":        client.Name,
			"description": client.Description,
			"clientId":    client.ClientID,
		},
		"scopes": scopeObjs,
		"request": map[string]string{
			"client_id":             ar.ClientID,
			"redirect_uri":          ar.RedirectURI,
			"scope":                 ar.Scope,
			"state":                 ar.State,
			"nonce":                 ar.Nonce,
			"code_challenge":        ar.CodeChallenge,
			"code_challenge_method": ar.CodeChallengeMethod,
		},
	})
}

// APIOAuthAuthorizeDecision mirrors AuthorizeConfirm. Returns {location} for the
// SPA to navigate to (success code, or an error at the client redirect_uri).
func (h *Handler) APIOAuthAuthorizeDecision(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action              string `json:"action"`
		ClientID            string `json:"client_id"`
		RedirectURI         string `json:"redirect_uri"`
		Scope               string `json:"scope"`
		State               string `json:"state"`
		Nonce               string `json:"nonce"`
		CodeChallenge       string `json:"code_challenge"`
		CodeChallengeMethod string `json:"code_challenge_method"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Action != "allow" && req.Action != "deny" {
		apiErr(w, http.StatusBadRequest, "invalid_request", "授权操作无效")
		return
	}
	ar := authRequest{
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	}

	client, err := h.st.GetClientByClientID(r.Context(), ar.ClientID)
	if err != nil || !validRedirectURI(client.RedirectURIs, ar.RedirectURI) {
		apiErr(w, http.StatusBadRequest, "invalid_client", "应用标识或回调地址无效")
		return
	}
	reqScopes := normalizeScopes(scopeList(ar.Scope))
	if len(reqScopes) == 0 {
		apiErr(w, http.StatusBadRequest, "invalid_scope", "至少需要一个权限范围")
		return
	}
	if !scopesSubset(reqScopes, client.Scopes) {
		apiErr(w, http.StatusBadRequest, "invalid_scope", "请求的权限范围不在应用允许列表中")
		return
	}
	if ar.CodeChallengeMethod == "" && ar.CodeChallenge != "" {
		ar.CodeChallengeMethod = "plain"
	}
	if ar.CodeChallenge != "" && ar.CodeChallengeMethod != "S256" && ar.CodeChallengeMethod != "plain" {
		apiErr(w, http.StatusBadRequest, "invalid_request", "不支持的挑战校验方式")
		return
	}
	if ar.CodeChallenge == "" && ar.CodeChallengeMethod != "" {
		apiErr(w, http.StatusBadRequest, "invalid_request", "设置挑战校验方式时必须提供挑战值")
		return
	}

	if req.Action == "deny" {
		loc, uerr := appendRedirectParams(ar.RedirectURI, map[string]string{
			"error":             "access_denied",
			"error_description": "用户拒绝授权",
			"state":             ar.State,
		})
		if uerr != nil {
			apiErr(w, http.StatusBadRequest, "invalid_request", "回调地址无效")
			return
		}
		apiOK(w, http.StatusOK, map[string]any{"location": loc})
		return
	}

	u := h.currentUser(r)
	if !h.st.UserCanAccessClient(r.Context(), u, client.BaseAccess, client.AllowedGroups) {
		apiErr(w, http.StatusForbidden, "access_denied", "当前账户不满足应用访问策略")
		return
	}

	code := store.RandomHex(24)
	if err := h.st.CreateAuthCode(r.Context(), code, ar.ClientID, u.ID, ar.RedirectURI, reqScopes,
		ar.CodeChallenge, ar.CodeChallengeMethod, ar.Nonce); err != nil {
		loc, uerr := appendRedirectParams(ar.RedirectURI, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
			"state":             ar.State,
		})
		if uerr != nil {
			apiErr(w, http.StatusBadRequest, "invalid_request", "回调地址无效")
			return
		}
		apiOK(w, http.StatusOK, map[string]any{"location": loc})
		return
	}

	redir, err := appendRedirectParams(ar.RedirectURI, map[string]string{
		"code":  code,
		"state": ar.State,
	})
	if err != nil {
		apiErr(w, http.StatusBadRequest, "invalid_request", "回调地址无效")
		return
	}
	apiOK(w, http.StatusOK, map[string]any{"location": redir})
}

// ── Home / legal content ────────────────────────────────────────────────────

type oauthHomeProjectDTO struct {
	ID        string   `json:"id"`
	Slug      string   `json:"slug"`
	NameZH    string   `json:"nameZH"`
	NameEN    string   `json:"nameEN"`
	DescZH    string   `json:"descZH"`
	DescEN    string   `json:"descEN"`
	Status    string   `json:"status"`
	URL       string   `json:"url"`
	Tags      []string `json:"tags"`
	Featured  bool     `json:"featured"`
	SortOrder int      `json:"sortOrder"`
	ImageURL  string   `json:"imageUrl"`
}

type oauthHomeLinkDTO struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	Icon      string `json:"icon"`
	SortOrder int    `json:"sortOrder"`
}

func oauthParseTags(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{}
	}
	var tags []string
	if err := json.Unmarshal([]byte(raw), &tags); err != nil || tags == nil {
		return []string{}
	}
	return tags
}

func (h *Handler) APIHome(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	projects, _ := h.st.ListProjects(ctx)
	links, _ := h.st.ListFriendLinks(ctx)

	pj := make([]oauthHomeProjectDTO, 0, len(projects))
	for _, p := range projects {
		pj = append(pj, oauthHomeProjectDTO{
			ID: p.ID, Slug: p.Slug, NameZH: p.NameZH, NameEN: p.NameEN,
			DescZH: p.DescZH, DescEN: p.DescEN, Status: p.Status, URL: p.URL,
			Tags: oauthParseTags(p.Tags), Featured: p.Featured, SortOrder: p.SortOrder,
			ImageURL: p.ImageURL,
		})
	}
	lk := make([]oauthHomeLinkDTO, 0, len(links))
	for _, l := range links {
		lk = append(lk, oauthHomeLinkDTO{ID: l.ID, Name: l.Name, URL: l.URL, Icon: l.Icon, SortOrder: l.SortOrder})
	}
	apiOK(w, http.StatusOK, map[string]any{"projects": pj, "links": lk})
}

func (h *Handler) APITOS(w http.ResponseWriter, r *http.Request) {
	apiOK(w, http.StatusOK, map[string]any{"content": h.st.GetSetting(r.Context(), "tos_content")})
}

func (h *Handler) APIPrivacy(w http.ResponseWriter, r *http.Request) {
	apiOK(w, http.StatusOK, map[string]any{"content": h.st.GetSetting(r.Context(), "privacy_content")})
}

// ── External identity bind ──────────────────────────────────────────────────

// prepareProviderAuthURL builds (and persists the state for) an external
// provider authorization URL without writing the HTTP response, so the SPA can
// receive the URL as JSON and navigate to it. Mirrors startProviderAuthFlow.
func (h *Handler) prepareProviderAuthURL(r *http.Request, provider *store.OIDCProvider, next, stateUserID string) (string, error) {
	doc, isOIDC, err := resolveRPProviderConfig(provider)
	if err != nil {
		return "", fmt.Errorf("外部登录配置加载失败")
	}
	state := store.RandomHex(16)
	nonce := ""
	if isOIDC {
		nonce = store.RandomHex(16)
	}
	verifier := store.RandomHex(32)
	scopes := normalizeScopes(strings.Fields(provider.Scopes))
	if len(scopes) == 0 {
		if isOIDC {
			scopes = defaultProviderScopes(providerTypeOIDC)
		} else {
			scopes = defaultProviderScopes(providerTypeOAuth2)
		}
	}
	if isOIDC && !containsScope(scopes, "openid") {
		return "", fmt.Errorf("OIDC 登录方式必须包含 openid 权限范围")
	}
	if err := h.st.CreateOIDCState(r.Context(), state, provider.Slug, stateUserID, nonce, verifier, safeNextPath(next, "/profile")); err != nil {
		return "", fmt.Errorf("登录状态创建失败，请稍后重试")
	}
	hv := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hv[:])
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", provider.ClientID)
	params.Set("redirect_uri", h.providerCallbackURL(r, provider.Slug))
	params.Set("scope", strings.Join(scopes, " "))
	params.Set("state", state)
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")
	if isOIDC {
		params.Set("nonce", nonce)
	}
	return doc.AuthorizationEndpoint + "?" + params.Encode(), nil
}

func (h *Handler) APIProfileIdentityBind(w http.ResponseWriter, r *http.Request) {
	u := h.currentUser(r)
	slug := r.PathValue("slug")
	ctx := r.Context()
	p, err := h.st.GetOIDCProviderBySlug(ctx, slug)
	if err != nil || !p.Enabled {
		apiErr(w, http.StatusNotFound, "not_found", "该登录方式不可用")
		return
	}
	if _, err := h.st.GetUserIdentityByUserAndProvider(ctx, u.ID, slug); err == nil {
		apiErr(w, http.StatusConflict, "conflict", "该登录方式已绑定")
		return
	} else if !isErrNoRows(err) {
		apiErr(w, http.StatusInternalServerError, "server_error", "读取绑定状态失败")
		return
	}
	p.ProviderType = normalizeProviderType(p.ProviderType)
	authURL, err := h.prepareProviderAuthURL(r, p, "/profile", u.ID)
	if err != nil {
		apiErr(w, http.StatusBadGateway, "provider_error", err.Error())
		return
	}
	apiOK(w, http.StatusOK, map[string]any{"location": authURL})
}
