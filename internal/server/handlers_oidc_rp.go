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
	"strconv"
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
		return nil, fmt.Errorf("获取发现文档失败：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("获取发现文档返回异常状态：%d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var d rpDiscovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("解析发现文档失败：%w", err)
	}

	if d.Issuer == "" || d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return nil, fmt.Errorf("发现文档缺少必填字段")
	}
	if !isAllowedAbsoluteURL(d.Issuer) || !isAllowedAbsoluteURL(d.AuthorizationEndpoint) ||
		!isAllowedAbsoluteURL(d.TokenEndpoint) || !isAllowedAbsoluteURL(d.JWKSURI) {
		return nil, fmt.Errorf("发现文档包含不受支持的地址")
	}
	if d.UserinfoEndpoint != "" && !isAllowedAbsoluteURL(d.UserinfoEndpoint) {
		return nil, fmt.Errorf("发现文档包含不受支持的用户信息地址")
	}

	wantIssuer, err := canonicalIssuerURL(issuerURL)
	if err != nil {
		return nil, err
	}
	gotIssuer, err := canonicalIssuerURL(d.Issuer)
	if err != nil {
		return nil, fmt.Errorf("发现文档发行方无效：%w", err)
	}
	if wantIssuer != gotIssuer {
		return nil, fmt.Errorf("发现文档发行方不匹配")
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
		return nil, fmt.Errorf("获取密钥清单失败：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("获取密钥清单返回异常状态：%d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	var jwks rpJWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("解析密钥清单失败：%w", err)
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
		// 即使没有密钥标识也保留，只有一把密钥时可回退使用。
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("密钥清单中没有可用的加密密钥")
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
		return nil, fmt.Errorf("指数无效")
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = (e << 8) + int(b)
	}
	if n.Sign() <= 0 || e <= 1 {
		return nil, fmt.Errorf("密钥无效")
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
			return nil, fmt.Errorf("缺少签名算法")
		}
		alg := t.Method.Alg()
		if alg != jwt.SigningMethodRS256.Alg() &&
			alg != jwt.SigningMethodRS384.Alg() &&
			alg != jwt.SigningMethodRS512.Alg() {
			return nil, fmt.Errorf("不支持的身份令牌算法：%s", alg)
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
		return nil, fmt.Errorf("未找到身份令牌对应密钥")
	}, jwt.WithIssuer(doc.Issuer), jwt.WithAudience(clientID), jwt.WithLeeway(60*time.Second))
	if err != nil {
		return nil, fmt.Errorf("校验身份令牌失败：%w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("身份令牌无效")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("身份令牌声明无效")
	}
	if nonce != "" {
		got := stringClaim(claims, "nonce")
		if got == "" || got != nonce {
			return nil, fmt.Errorf("身份令牌随机串不匹配")
		}
	}
	return claims, nil
}

func canonicalIssuerURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !u.IsAbs() || u.Host == "" {
		return "", fmt.Errorf("发行方地址无效")
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.Path = strings.TrimRight(u.Path, "/")
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + u.Path, nil
}

func resolveRPProviderConfig(provider *store.OIDCProvider) (*rpDiscovery, bool, error) {
	mode := normalizeProviderType(provider.ProviderType)
	if mode == providerTypeOAuth2 {
		authorizationURL := strings.TrimSpace(provider.AuthorizationURL)
		tokenURL := strings.TrimSpace(provider.TokenURL)
		userinfoURL := strings.TrimSpace(provider.UserinfoURL)
		if authorizationURL == "" || tokenURL == "" || userinfoURL == "" {
			return nil, false, fmt.Errorf("oauth2 provider endpoints are incomplete")
		}
		if !isAllowedAbsoluteURL(authorizationURL) ||
			!isAllowedAbsoluteURL(tokenURL) ||
			!isAllowedAbsoluteURL(userinfoURL) {
			return nil, false, fmt.Errorf("oauth2 provider endpoints are invalid")
		}
		return &rpDiscovery{
			AuthorizationEndpoint: authorizationURL,
			TokenEndpoint:         tokenURL,
			UserinfoEndpoint:      userinfoURL,
		}, false, nil
	}
	doc, err := fetchRPDiscovery(strings.TrimSpace(provider.IssuerURL))
	if err != nil {
		return nil, true, err
	}
	return doc, true, nil
}

func (h *Handler) providerCallbackURL(r *http.Request, slug string) string {
	base := strings.TrimRight(strings.TrimSpace(h.cfg.Issuer), "/")
	if host := strings.TrimSpace(r.Host); host != "" {
		scheme := "https"
		if fp := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); fp != "" {
			scheme = fp
		} else if r.TLS == nil {
			scheme = "http"
		}
		if fh := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); fh != "" {
			host = fh
		}
		base = scheme + "://" + host
	}
	if !isAllowedAbsoluteURL(base) {
		base = strings.TrimRight(strings.TrimSpace(h.cfg.Issuer), "/")
	}
	return base + "/auth/oidc/" + slug + "/callback"
}

// GET /auth/oidc/{slug}
func (h *Handler) OIDCProviderLogin(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	provider, err := h.st.GetOIDCProviderBySlug(r.Context(), slug)
	if err != nil || !provider.Enabled {
		h.renderError(w, r, http.StatusNotFound, "Login method unavailable", "The requested external login method does not exist or is disabled.")
		return
	}
	provider.ProviderType = normalizeProviderType(provider.ProviderType)

	doc, isOIDC, err := resolveRPProviderConfig(provider)
	if err != nil {
		h.renderError(w, r, http.StatusBadGateway, "Provider configuration error", "Failed to load external login configuration.")
		return
	}

	state := store.RandomHex(16)
	nonce := ""
	if isOIDC {
		nonce = store.RandomHex(16)
	}
	verifier := store.RandomHex(32)
	next := safeNextPath(r.URL.Query().Get("next"), "/profile")
	scopes := normalizeScopes(strings.Fields(provider.Scopes))
	if len(scopes) == 0 {
		if isOIDC {
			scopes = defaultProviderScopes(providerTypeOIDC)
		} else {
			scopes = defaultProviderScopes(providerTypeOAuth2)
		}
	}
	if isOIDC && !containsScope(scopes, "openid") {
		h.renderError(w, r, http.StatusBadRequest, "Invalid provider scopes", "OIDC providers must request the openid scope.")
		return
	}

	if err := h.st.CreateOIDCState(r.Context(), state, slug, nonce, verifier, next); err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "Login state creation failed", "Please retry in a moment.")
		return
	}

	hv := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hv[:])

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", provider.ClientID)
	params.Set("redirect_uri", h.providerCallbackURL(r, slug))
	params.Set("scope", strings.Join(scopes, " "))
	params.Set("state", state)
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")
	if isOIDC {
		params.Set("nonce", nonce)
	}

	http.Redirect(w, r, doc.AuthorizationEndpoint+"?"+params.Encode(), http.StatusFound)
}

// GET /auth/oidc/{slug}/callback
func (h *Handler) OIDCProviderCallback(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")

	if r.URL.Query().Get("error") != "" {
		h.renderError(w, r, http.StatusBadRequest, "External login denied", "The provider rejected this login request.")
		return
	}

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		h.renderError(w, r, http.StatusBadRequest, "Login failed", "Missing authorization code.")
		return
	}
	stateVal := strings.TrimSpace(r.URL.Query().Get("state"))
	if stateVal == "" {
		h.renderError(w, r, http.StatusBadRequest, "Login failed", "Missing state parameter.")
		return
	}
	st, err := h.st.ConsumeOIDCState(r.Context(), stateVal)
	if err != nil || st.Provider != slug {
		h.renderError(w, r, http.StatusBadRequest, "Invalid login state", "Please start login again.")
		return
	}

	provider, err := h.st.GetOIDCProviderBySlug(r.Context(), slug)
	if err != nil || !provider.Enabled {
		h.renderError(w, r, http.StatusNotFound, "Login method unavailable", "The requested external login method does not exist or is disabled.")
		return
	}
	provider.ProviderType = normalizeProviderType(provider.ProviderType)

	doc, isOIDC, err := resolveRPProviderConfig(provider)
	if err != nil {
		h.renderError(w, r, http.StatusBadGateway, "Provider configuration error", "Failed to load external login configuration.")
		return
	}

	tok, err := rpExchangeCode(doc.TokenEndpoint, provider, code, h.providerCallbackURL(r, slug), st.Verifier)
	if err != nil {
		h.renderError(w, r, http.StatusBadGateway, "Token exchange failed", "Failed to exchange authorization code.")
		return
	}

	var (
		subject       string
		email         string
		emailVerified bool
		name          string
		avatar        string
	)

	if isOIDC {
		if tok.IDToken == "" {
			h.renderError(w, r, http.StatusBadGateway, "Login failed", "Missing ID token from OIDC provider.")
			return
		}

		idClaims, verifyErr := verifyProviderIDToken(tok.IDToken, doc, provider.ClientID, st.Nonce)
		if verifyErr != nil {
			h.renderError(w, r, http.StatusBadGateway, "ID token verification failed", verifyErr.Error())
			return
		}

		subject = stringClaim(idClaims, "sub")
		email = strings.ToLower(strings.TrimSpace(stringClaim(idClaims, "email")))
		emailVerified = boolClaim(idClaims, "email_verified")
		name = stringClaim(idClaims, "name")
		if name == "" {
			name = stringClaim(idClaims, "preferred_username")
		}
		if name == "" {
			name = stringClaim(idClaims, "username")
		}
		avatar = stringClaim(idClaims, "picture")
		if avatar == "" {
			avatar = stringClaim(idClaims, "profile_image_url")
		}
		if avatar == "" {
			avatar = stringClaim(idClaims, "avatar_url")
		}

		if doc.UserinfoEndpoint != "" {
			usub, uemail, uverified, uname, upic, uiErr := rpUserInfo(doc.UserinfoEndpoint, tok.AccessToken)
			if uiErr == nil {
				if subject != "" && usub != "" && usub != subject {
					h.renderError(w, r, http.StatusBadGateway, "Login failed", "UserInfo subject does not match ID token subject.")
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
	} else {
		usub, uemail, uverified, uname, upic, uiErr := rpUserInfo(doc.UserinfoEndpoint, tok.AccessToken)
		if uiErr != nil {
			h.renderError(w, r, http.StatusBadGateway, "User profile fetch failed", uiErr.Error())
			return
		}
		subject = usub
		email = strings.ToLower(strings.TrimSpace(uemail))
		emailVerified = uverified
		name = uname
		avatar = upic
	}

	if subject == "" {
		h.renderError(w, r, http.StatusBadGateway, "User identity missing", "Provider response did not include a stable subject identifier.")
		return
	}

	ctx := r.Context()
	u, err := h.st.GetUserByIdentity(ctx, slug, subject)
	if err != nil {
		if !isErrNoRows(err) {
			h.renderError(w, r, http.StatusInternalServerError, "Identity lookup failed", err.Error())
			return
		}
		if email != "" {
			existing, emailErr := h.st.GetUserByEmail(ctx, email)
			if emailErr == nil {
				u = existing
			} else if !isErrNoRows(emailErr) {
				h.renderError(w, r, http.StatusInternalServerError, "User lookup failed", emailErr.Error())
				return
			}
		}

		if u == nil {
			if !provider.AutoRegister {
				h.renderError(w, r, http.StatusForbidden, "Registration disabled", "Auto registration is disabled for this provider.")
				return
			}
			if name == "" {
				if email != "" {
					name = email
				} else {
					name = "External Login User"
				}
			}
			createEmail := email
			if createEmail == "" || !emailVerified {
				createEmail = syntheticOIDCEmail(slug, subject)
			}
			isVerifiedEmail := emailVerified && email != "" && strings.EqualFold(createEmail, email)
			u, err = h.st.CreateUserWithEmailVerified(ctx, createEmail, store.RandomHex(32), name, "user", isVerifiedEmail)
			if err != nil {
				h.renderError(w, r, http.StatusInternalServerError, "User creation failed", err.Error())
				return
			}
			if err := h.st.ClearPassword(ctx, u.ID); err != nil {
				h.renderError(w, r, http.StatusInternalServerError, "Account hardening failed", err.Error())
				return
			}
			u.PassHash = ""
			_ = h.st.SetRequirePasswordChange(ctx, u.ID, true)
			u.RequirePasswordChange = true
			if avatar != "" {
				_ = h.st.UpdateUserAvatar(ctx, u.ID, avatar)
			}
		}

		if err := h.st.LinkIdentity(ctx, u.ID, slug, subject); err != nil {
			h.renderError(w, r, http.StatusInternalServerError, "Identity binding failed", err.Error())
			return
		}
	}

	if !u.Active {
		h.renderError(w, r, http.StatusForbidden, "Account disabled", "Please contact an administrator.")
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

	if u.RequirePasswordChange {
		sid, _ := h.st.CreateSession(ctx, u.ID)
		h.setSessionCookie(w, sid)
		http.Redirect(w, r, "/profile/change-password", http.StatusFound)
		return
	}

	sid, err := h.st.CreateSession(ctx, u.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "Session creation failed", err.Error())
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
	// 大多数提供商支持基础认证；失败时回退为表单提交密钥。
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
		return nil, 0, fmt.Errorf("令牌请求失败：%w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	var t rpTokenResp
	if err := json.Unmarshal(body, &t); err != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil, resp.StatusCode, fmt.Errorf("解析令牌响应失败：%w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if t.Error != "" {
			return nil, resp.StatusCode, fmt.Errorf("%s: %s", t.Error, t.ErrorDesc)
		}
		return nil, resp.StatusCode, fmt.Errorf("令牌端点状态异常：%d", resp.StatusCode)
	}
	if t.Error != "" {
		return nil, resp.StatusCode, fmt.Errorf("%s: %s", t.Error, t.ErrorDesc)
	}
	if t.AccessToken == "" {
		return nil, resp.StatusCode, fmt.Errorf("令牌响应缺少访问令牌")
	}
	return &t, resp.StatusCode, nil
}

func rpUserInfo(endpoint, accessToken string) (sub, email string, emailVerified bool, name, picture string, err error) {
	if strings.TrimSpace(endpoint) == "" {
		err = fmt.Errorf("缺少用户信息端点")
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
		err = fmt.Errorf("用户信息端点状态异常：%d", resp.StatusCode)
		return
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var claims map[string]any
	if err = json.Unmarshal(body, &claims); err != nil {
		return
	}

	sub = stringClaim(claims, "sub")
	if sub == "" {
		sub = stringClaim(claims, "id")
	}
	if sub == "" {
		sub = stringClaim(claims, "user_id")
	}
	if sub == "" {
		if n, ok := claims["id"].(float64); ok {
			sub = strconv.FormatInt(int64(n), 10)
		}
	}
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
