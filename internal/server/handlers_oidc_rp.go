package server

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"transmtf.com/oidc/internal/store"
)

type rpDiscovery struct {
	Issuer                string `json:"issuer"`
	JWKSURI               string `json:"jwks_uri"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

type rpRSAJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type rpJWKS struct {
	Keys []rpRSAJWK `json:"keys"`
}

var (
	rpHTTPClient = &http.Client{Timeout: 10 * time.Second}

	rpCacheMu sync.RWMutex
	rpCache   = map[string]*rpDiscovery{}
	rpCacheAt = map[string]time.Time{}

	rpJWKSCacheMu sync.RWMutex
	rpJWKSCache   = map[string]map[string]*rsa.PublicKey{}
	rpJWKSCacheAt = map[string]time.Time{}
)

func fetchRPDiscovery(issuerURL string) (*rpDiscovery, error) {
	rpCacheMu.RLock()
	doc, ok := rpCache[issuerURL]
	at := rpCacheAt[issuerURL]
	rpCacheMu.RUnlock()
	if ok && time.Since(at) < 6*time.Hour {
		return doc, nil
	}

	wellKnown := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"
	resp, err := rpHTTPClient.Get(wellKnown) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("fetch discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch discovery: unexpected status %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var d rpDiscovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("parse discovery: %w", err)
	}

	if d.Issuer == "" || d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return nil, fmt.Errorf("discovery missing required fields")
	}
	if !isAllowedAbsoluteURL(d.Issuer) || !isAllowedAbsoluteURL(d.AuthorizationEndpoint) ||
		!isAllowedAbsoluteURL(d.TokenEndpoint) || !isAllowedAbsoluteURL(d.JWKSURI) {
		return nil, fmt.Errorf("discovery contains unsupported URLs")
	}
	if d.UserinfoEndpoint != "" && !isAllowedAbsoluteURL(d.UserinfoEndpoint) {
		return nil, fmt.Errorf("discovery contains unsupported userinfo endpoint")
	}

	wantIssuer, err := canonicalIssuerURL(issuerURL)
	if err != nil {
		return nil, err
	}
	gotIssuer, err := canonicalIssuerURL(d.Issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid discovery issuer: %w", err)
	}
	if wantIssuer != gotIssuer {
		return nil, fmt.Errorf("discovery issuer mismatch")
	}

	rpCacheMu.Lock()
	rpCache[issuerURL] = &d
	rpCacheAt[issuerURL] = time.Now()
	rpCacheMu.Unlock()
	return &d, nil
}

func fetchRPJWKS(jwksURL string) (map[string]*rsa.PublicKey, error) {
	rpJWKSCacheMu.RLock()
	keys, ok := rpJWKSCache[jwksURL]
	at := rpJWKSCacheAt[jwksURL]
	rpJWKSCacheMu.RUnlock()
	if ok && time.Since(at) < 6*time.Hour {
		return keys, nil
	}

	resp, err := rpHTTPClient.Get(jwksURL) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch jwks: unexpected status %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	var jwks rpJWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}

	out := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if !strings.EqualFold(k.Kty, "RSA") || k.N == "" || k.E == "" {
			continue
		}
		pub, err := rsaKeyFromJWK(k.N, k.E)
		if err != nil {
			continue
		}
		// Keep key even without kid; keyfunc can fallback when only one key exists.
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("jwks has no usable RSA keys")
	}

	rpJWKSCacheMu.Lock()
	rpJWKSCache[jwksURL] = out
	rpJWKSCacheAt[jwksURL] = time.Now()
	rpJWKSCacheMu.Unlock()
	return out, nil
}

func rsaKeyFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	if len(eBytes) == 0 {
		return nil, fmt.Errorf("invalid exponent")
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = (e << 8) + int(b)
	}
	if n.Sign() <= 0 || e <= 1 {
		return nil, fmt.Errorf("invalid rsa key")
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

func verifyProviderIDToken(idToken string, doc *rpDiscovery, clientID, nonce string) (map[string]any, error) {
	keys, err := fetchRPJWKS(doc.JWKSURI)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(idToken, func(t *jwt.Token) (any, error) {
		if t.Method == nil {
			return nil, fmt.Errorf("missing signing method")
		}
		alg := t.Method.Alg()
		if alg != jwt.SigningMethodRS256.Alg() &&
			alg != jwt.SigningMethodRS384.Alg() &&
			alg != jwt.SigningMethodRS512.Alg() {
			return nil, fmt.Errorf("unsupported id_token alg: %s", alg)
		}

		kid, _ := t.Header["kid"].(string)
		if kid != "" {
			if k, ok := keys[kid]; ok {
				return k, nil
			}
		}
		if len(keys) == 1 {
			for _, k := range keys {
				return k, nil
			}
		}
		return nil, fmt.Errorf("id_token key not found")
	}, jwt.WithIssuer(doc.Issuer), jwt.WithAudience(clientID), jwt.WithLeeway(60*time.Second))
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("id_token invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid id_token claims")
	}
	if nonce != "" {
		got := stringClaim(claims, "nonce")
		if got == "" || got != nonce {
			return nil, fmt.Errorf("id_token nonce mismatch")
		}
	}
	return claims, nil
}

func canonicalIssuerURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !u.IsAbs() || u.Host == "" {
		return "", fmt.Errorf("invalid issuer URL")
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.Path = strings.TrimRight(u.Path, "/")
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + u.Path, nil
}

// GET /auth/oidc/{slug}
func (h *Handler) OIDCProviderLogin(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	provider, err := h.st.GetOIDCProviderBySlug(r.Context(), slug)
	if err != nil || !provider.Enabled {
		h.renderError(w, r, http.StatusNotFound, "登录方式不存在", slug)
		return
	}

	doc, err := fetchRPDiscovery(provider.IssuerURL)
	if err != nil {
		h.renderError(w, r, http.StatusBadGateway, "无法获取登录配置", err.Error())
		return
	}

	state := store.RandomHex(16)
	nonce := store.RandomHex(16)
	verifier := store.RandomHex(32)
	next := safeNextPath(r.URL.Query().Get("next"), "/profile")
	scopes := normalizeScopes(strings.Fields(provider.Scopes))
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	if !containsScope(scopes, "openid") {
		h.renderError(w, r, http.StatusBadRequest, "登录配置错误", "provider scopes must include openid")
		return
	}

	if err := h.st.CreateOIDCState(r.Context(), state, slug, nonce, verifier, next); err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "状态创建失败", err.Error())
		return
	}

	hv := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hv[:])

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", provider.ClientID)
	params.Set("redirect_uri", h.cfg.Issuer+"/auth/oidc/"+slug+"/callback")
	params.Set("scope", strings.Join(scopes, " "))
	params.Set("state", state)
	params.Set("nonce", nonce)
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")

	http.Redirect(w, r, doc.AuthorizationEndpoint+"?"+params.Encode(), http.StatusFound)
}

// GET /auth/oidc/{slug}/callback
func (h *Handler) OIDCProviderCallback(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")

	if errCode := r.URL.Query().Get("error"); errCode != "" {
		desc := r.URL.Query().Get("error_description")
		h.renderError(w, r, http.StatusBadRequest, "登录被拒绝", errCode+": "+desc)
		return
	}

	code := r.URL.Query().Get("code")
	if strings.TrimSpace(code) == "" {
		h.renderError(w, r, http.StatusBadRequest, "登录失败", "missing code")
		return
	}
	stateVal := r.URL.Query().Get("state")
	if strings.TrimSpace(stateVal) == "" {
		h.renderError(w, r, http.StatusBadRequest, "登录失败", "missing state")
		return
	}
	st, err := h.st.ConsumeOIDCState(r.Context(), stateVal)
	if err != nil || st.Provider != slug {
		h.renderError(w, r, http.StatusBadRequest, "登录状态无效", "请重新发起登录")
		return
	}

	provider, err := h.st.GetOIDCProviderBySlug(r.Context(), slug)
	if err != nil || !provider.Enabled {
		h.renderError(w, r, http.StatusNotFound, "登录方式不存在", slug)
		return
	}

	doc, err := fetchRPDiscovery(provider.IssuerURL)
	if err != nil {
		h.renderError(w, r, http.StatusBadGateway, "无法获取登录配置", err.Error())
		return
	}

	tok, err := rpExchangeCode(doc.TokenEndpoint, provider, code, h.cfg.Issuer+"/auth/oidc/"+slug+"/callback", st.Verifier)
	if err != nil {
		h.renderError(w, r, http.StatusBadGateway, "Token 交换失败", err.Error())
		return
	}
	if tok.IDToken == "" {
		h.renderError(w, r, http.StatusBadGateway, "登录失败", "缺少 id_token")
		return
	}

	idClaims, err := verifyProviderIDToken(tok.IDToken, doc, provider.ClientID, st.Nonce)
	if err != nil {
		h.renderError(w, r, http.StatusBadGateway, "ID Token 校验失败", err.Error())
		return
	}

	subject := stringClaim(idClaims, "sub")
	email := strings.ToLower(strings.TrimSpace(stringClaim(idClaims, "email")))
	emailVerified := boolClaim(idClaims, "email_verified")
	name := stringClaim(idClaims, "name")
	if name == "" {
		name = stringClaim(idClaims, "preferred_username")
	}
	if name == "" {
		name = stringClaim(idClaims, "username")
	}
	avatar := stringClaim(idClaims, "picture")
	if avatar == "" {
		avatar = stringClaim(idClaims, "profile_image_url")
	}
	if avatar == "" {
		avatar = stringClaim(idClaims, "avatar_url")
	}

	// Pull userinfo to enrich claims; enforce sub consistency if present.
	if doc.UserinfoEndpoint != "" {
		usub, uemail, uverified, uname, upic, uiErr := rpUserInfo(doc.UserinfoEndpoint, tok.AccessToken)
		if uiErr == nil {
			if subject != "" && usub != "" && usub != subject {
				h.renderError(w, r, http.StatusBadGateway, "登录失败", "userinfo sub mismatch")
				return
			}
			if subject == "" {
				subject = usub
			}
			if email == "" {
				email = strings.ToLower(strings.TrimSpace(uemail))
			}
			if !emailVerified {
				emailVerified = uverified
			}
			if name == "" {
				name = uname
			}
			if avatar == "" {
				avatar = upic
			}
		}
	}

	if subject == "" {
		h.renderError(w, r, http.StatusBadGateway, "获取用户信息失败", "missing sub")
		return
	}

	ctx := r.Context()
	u, err := h.st.GetUserByIdentity(ctx, slug, subject)
	if err != nil {
		// Only verified email can link to an existing local account.
		if emailVerified && email != "" {
			existing, emailErr := h.st.GetUserByEmail(ctx, email)
			if emailErr == nil {
				u = existing
			}
		}

		if u == nil {
			if name == "" {
				if email != "" {
					name = email
				} else {
					name = "OIDC User"
				}
			}
			createEmail := email
			if createEmail == "" || !emailVerified {
				createEmail = syntheticOIDCEmail(slug, subject)
			}
			u, err = h.st.CreateUser(ctx, createEmail, store.RandomHex(32), name, "user")
			if err != nil {
				h.renderError(w, r, http.StatusInternalServerError, "创建账号失败", err.Error())
				return
			}
			if avatar != "" {
				_ = h.st.UpdateUserAvatar(ctx, u.ID, avatar)
			}
		}

		if err := h.st.LinkIdentity(ctx, u.ID, slug, subject); err != nil {
			h.renderError(w, r, http.StatusInternalServerError, "身份绑定失败", err.Error())
			return
		}
	}

	if !u.Active {
		h.renderError(w, r, http.StatusForbidden, "账号已停用", "请联系管理员")
		return
	}
	if name != "" && strings.TrimSpace(u.DisplayName) == "" {
		_ = h.st.UpdateUser(ctx, u.ID, name, u.Role, u.Active)
		u.DisplayName = name
	}
	if avatar != "" && strings.TrimSpace(u.AvatarURL) == "" {
		_ = h.st.UpdateUserAvatar(ctx, u.ID, avatar)
		u.AvatarURL = avatar
	}
	if h.startSecondFactor(w, r, u, st.Redirect) {
		return
	}

	sid, err := h.st.CreateSession(ctx, u.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "会话创建失败", err.Error())
		return
	}
	h.setSessionCookie(w, sid)
	http.Redirect(w, r, safeNextPath(st.Redirect, "/profile"), http.StatusFound)
}

type rpTokenResp struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

func rpExchangeCode(tokenEndpoint string, p *store.OIDCProvider, code, redirectURI, verifier string) (*rpTokenResp, error) {
	// Most providers accept client_secret_basic. If not, retry with client_secret_post.
	tok, status, err := rpExchangeCodeOnce(tokenEndpoint, p, code, redirectURI, verifier, true)
	if err == nil {
		return tok, nil
	}
	msg := strings.ToLower(err.Error())
	if status == http.StatusUnauthorized || status == http.StatusBadRequest || strings.Contains(msg, "invalid_client") {
		tok2, _, err2 := rpExchangeCodeOnce(tokenEndpoint, p, code, redirectURI, verifier, false)
		if err2 == nil {
			return tok2, nil
		}
		return nil, err2
	}
	return nil, err
}

func rpExchangeCodeOnce(tokenEndpoint string, p *store.OIDCProvider, code, redirectURI, verifier string, useBasic bool) (*rpTokenResp, int, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", p.ClientID)
	form.Set("code_verifier", verifier)
	if !useBasic {
		form.Set("client_secret", p.ClientSecret)
	}

	req, err := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if useBasic {
		req.SetBasicAuth(p.ClientID, p.ClientSecret)
	}

	resp, err := rpHTTPClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	var t rpTokenResp
	if err := json.Unmarshal(body, &t); err != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil, resp.StatusCode, fmt.Errorf("parse token response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if t.Error != "" {
			return nil, resp.StatusCode, fmt.Errorf("%s: %s", t.Error, t.ErrorDesc)
		}
		return nil, resp.StatusCode, fmt.Errorf("token endpoint status: %d", resp.StatusCode)
	}
	if t.Error != "" {
		return nil, resp.StatusCode, fmt.Errorf("%s: %s", t.Error, t.ErrorDesc)
	}
	if t.AccessToken == "" {
		return nil, resp.StatusCode, fmt.Errorf("token response missing access_token")
	}
	return &t, resp.StatusCode, nil
}

func rpUserInfo(endpoint, accessToken string) (sub, email string, emailVerified bool, name, picture string, err error) {
	if strings.TrimSpace(endpoint) == "" {
		err = fmt.Errorf("missing userinfo endpoint")
		return
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := rpHTTPClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err = fmt.Errorf("userinfo endpoint status: %d", resp.StatusCode)
		return
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var claims map[string]any
	if err = json.Unmarshal(body, &claims); err != nil {
		return
	}

	sub = stringClaim(claims, "sub")
	email = stringClaim(claims, "email")
	if email == "" {
		email = stringClaim(claims, "upn")
	}
	emailVerified = boolClaim(claims, "email_verified")
	name = stringClaim(claims, "name")
	if name == "" {
		name = stringClaim(claims, "preferred_username")
	}
	if name == "" {
		name = stringClaim(claims, "username")
	}
	picture = stringClaim(claims, "picture")
	if picture == "" {
		picture = stringClaim(claims, "profile_image_url")
	}
	if picture == "" {
		picture = stringClaim(claims, "avatar_url")
	}
	return
}

func stringClaim(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func boolClaim(m map[string]any, key string) bool {
	v, ok := m[key]
	if !ok {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true") || x == "1"
	case float64:
		return x != 0
	default:
		return false
	}
}

func syntheticOIDCEmail(provider, subject string) string {
	sum := sha256.Sum256([]byte(provider + ":" + subject))
	return "oidc_" + base64.RawURLEncoding.EncodeToString(sum[:10]) + "@oidc.local"
}
