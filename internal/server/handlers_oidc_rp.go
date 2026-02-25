package server

import (
	"context"
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

func (h *Handler) startProviderAuthFlow(w http.ResponseWriter, r *http.Request, provider *store.OIDCProvider, next, stateUserID string) bool {
	doc, isOIDC, err := resolveRPProviderConfig(provider)
	if err != nil {
		h.renderError(w, r, http.StatusBadGateway, "Provider configuration error", "Failed to load external login configuration.")
		return false
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
		h.renderError(w, r, http.StatusBadRequest, "Invalid provider scopes", "OIDC providers must request the openid scope.")
		return false
	}

	if err := h.st.CreateOIDCState(r.Context(), state, provider.Slug, stateUserID, nonce, verifier, safeNextPath(next, "/profile")); err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "Login state creation failed", "Please retry in a moment.")
		return false
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

	statusCode := http.StatusFound
	if r.Method == http.MethodPost {
		// POST 发起的绑定流程使用 303，确保浏览器按导航跳转到授权页。
		statusCode = http.StatusSeeOther
	}
	http.Redirect(w, r, doc.AuthorizationEndpoint+"?"+params.Encode(), statusCode)
	return true
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
	next := safeNextPath(r.URL.Query().Get("next"), "/profile")
	_ = h.startProviderAuthFlow(w, r, provider, next, "")
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
	st, err := h.st.GetOIDCState(r.Context(), stateVal)
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
		username      string
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
		username = stringClaim(idClaims, "preferred_username")
		if username == "" {
			username = stringClaim(idClaims, "username")
		}
		if name == "" {
			name = username
		}
		avatar = stringClaim(idClaims, "picture")
		if avatar == "" {
			avatar = stringClaim(idClaims, "profile_image_url")
		}
		if avatar == "" {
			avatar = stringClaim(idClaims, "avatar_url")
		}

		if doc.UserinfoEndpoint != "" {
			usub, uemail, uverified, uname, uusername, upic, uiErr := rpUserInfo(doc.UserinfoEndpoint, tok.AccessToken)
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
				if username == "" {
					username = uusername
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
		usub, uemail, uverified, uname, uusername, upic, uiErr := rpUserInfo(doc.UserinfoEndpoint, tok.AccessToken)
		if uiErr != nil {
			h.renderError(w, r, http.StatusBadGateway, "User profile fetch failed", uiErr.Error())
			return
		}
		subject = usub
		email = strings.ToLower(strings.TrimSpace(uemail))
		emailVerified = uverified
		name = uname
		username = uusername
		avatar = upic
	}

	if isXProviderSlug(slug) {
		// X 的邮箱返回不稳定，避免自动使用外部邮箱。
		email = ""
		emailVerified = false
		if username != "" {
			name = username
		}
	}

	if subject == "" {
		h.renderError(w, r, http.StatusBadGateway, "User identity missing", "Provider response did not include a stable subject identifier.")
		return
	}
	if err := h.st.DeleteOIDCState(r.Context(), stateVal); err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "Login state cleanup failed", "Please start login again.")
		return
	}

	ctx := r.Context()
	if st.UserID != "" {
		h.finishProfileIdentityBinding(w, r, st, slug, subject)
		return
	}

	u, err := h.st.GetUserByIdentity(ctx, slug, subject)
	if err == nil {
		h.finishExternalLogin(w, r, u, st.Redirect)
		return
	}
	if !isErrNoRows(err) {
		h.renderError(w, r, http.StatusInternalServerError, "Identity lookup failed", err.Error())
		return
	}

	chID, chErr := h.st.CreateOIDCLoginChallenge(
		ctx,
		slug,
		subject,
		strings.TrimSpace(name),
		strings.TrimSpace(avatar),
		strings.TrimSpace(email),
		st.Redirect,
	)
	if chErr != nil {
		h.renderError(w, r, http.StatusInternalServerError, "Login flow setup failed", chErr.Error())
		return
	}
	http.Redirect(w, r, "/auth/oidc/first-login?challenge="+url.QueryEscape(chID), http.StatusFound)
}

// GET /auth/oidc/first-login
func (h *Handler) OIDCFirstLoginPage(w http.ResponseWriter, r *http.Request) {
	chID := strings.TrimSpace(r.URL.Query().Get("challenge"))
	if chID == "" {
		h.renderError(w, r, http.StatusBadRequest, "首次登录流程无效", "缺少流程挑战参数。")
		return
	}

	ctx := r.Context()
	ch, err := h.st.GetOIDCLoginChallenge(ctx, chID)
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, "首次登录流程已过期", "请重新发起外部授权登录。")
		return
	}
	providerName := ch.Provider
	if p, pErr := h.st.GetOIDCProviderBySlug(ctx, ch.Provider); pErr == nil && p != nil {
		providerName = p.Name
	}

	d := h.pageData(r, "首次使用外部登录")
	d.Data = map[string]any{
		"Challenge":    ch.ID,
		"ProviderSlug": ch.Provider,
		"ProviderName": providerName,
		"ProfileName":  ch.ProfileName,
		"ProfileAvatar": ch.ProfileAvatar,
		"ProfileEmail": ch.ProfileEmail,
	}
	h.render(w, "oidc_first_login", d)
}

// POST /auth/oidc/first-login
func (h *Handler) OIDCFirstLoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	chID := strings.TrimSpace(r.FormValue("challenge"))
	if chID == "" {
		h.renderError(w, r, http.StatusBadRequest, "首次登录流程无效", "缺少流程挑战参数。")
		return
	}
	ch, err := h.st.GetOIDCLoginChallenge(r.Context(), chID)
	if err != nil {
		h.renderError(w, r, http.StatusBadRequest, "首次登录流程已过期", "请重新发起外部授权登录。")
		return
	}

	action := strings.TrimSpace(r.FormValue("action"))
	switch action {
	case "bind":
		http.Redirect(w, r, "/login?oidc_challenge="+url.QueryEscape(ch.ID), http.StatusFound)
		return
	case "register":
		http.Redirect(w, r, "/register?oidc_challenge="+url.QueryEscape(ch.ID), http.StatusFound)
		return
	default:
		h.renderError(w, r, http.StatusBadRequest, "无效操作", "请选择绑定已有账户或注册新账户。")
		return
	}
}

func (h *Handler) finishProfileIdentityBinding(w http.ResponseWriter, r *http.Request, st *store.OIDCState, providerSlug, subject string) {
	ctx := r.Context()
	cur := h.currentUser(r)
	if cur == nil || cur.ID != st.UserID {
		h.renderError(w, r, http.StatusForbidden, "绑定失败", "当前会话与绑定账户不一致，请从个人资料页重新发起绑定。")
		return
	}
	existing, err := h.st.GetUserByIdentity(ctx, providerSlug, subject)
	if err == nil {
		if existing.ID == st.UserID {
			http.Redirect(w, r, "/profile?flash="+url.QueryEscape("该登录方式已绑定"), http.StatusFound)
			return
		}
		h.renderError(w, r, http.StatusConflict, "绑定失败", "该外部账号已绑定到其他本地账户。")
		return
	}
	if !isErrNoRows(err) {
		h.renderError(w, r, http.StatusInternalServerError, "绑定失败", err.Error())
		return
	}
	if err := h.st.LinkIdentity(ctx, st.UserID, providerSlug, subject); err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "绑定失败", err.Error())
		return
	}
	bound, bindErr := h.st.GetUserByIdentity(ctx, providerSlug, subject)
	if bindErr != nil || bound == nil || bound.ID != st.UserID {
		h.renderError(w, r, http.StatusConflict, "绑定失败", "该外部账号已绑定到其他本地账户。")
		return
	}
	http.Redirect(w, r, "/profile?flash="+url.QueryEscape("登录方式绑定成功"), http.StatusFound)
}

func (h *Handler) consumeOIDCLoginChallengeAndLink(ctx context.Context, u *store.User, challengeID string) (string, error) {
	if strings.TrimSpace(challengeID) == "" {
		return "", nil
	}
	ch, err := h.st.ConsumeOIDCLoginChallenge(ctx, strings.TrimSpace(challengeID))
	if err != nil {
		return "", fmt.Errorf("外部登录流程已过期，请重新发起授权")
	}

	existing, lookupErr := h.st.GetUserByIdentity(ctx, ch.Provider, ch.Subject)
	if lookupErr == nil {
		if existing.ID != u.ID {
			return "", fmt.Errorf("该外部账号已绑定到其他本地账户")
		}
		return safeNextPath(ch.Redirect, "/profile"), nil
	}
	if !isErrNoRows(lookupErr) {
		return "", lookupErr
	}

	if err := h.st.LinkIdentity(ctx, u.ID, ch.Provider, ch.Subject); err != nil {
		return "", err
	}
	bound, bindErr := h.st.GetUserByIdentity(ctx, ch.Provider, ch.Subject)
	if bindErr != nil || bound == nil || bound.ID != u.ID {
		return "", fmt.Errorf("该外部账号已绑定到其他本地账户")
	}
	// 首次绑定时，若本地头像/显示名为空，则用外部资料补齐。
	if strings.TrimSpace(u.AvatarURL) == "" && strings.TrimSpace(ch.ProfileAvatar) != "" {
		_ = h.st.UpdateUserAvatar(ctx, u.ID, strings.TrimSpace(ch.ProfileAvatar))
		u.AvatarURL = strings.TrimSpace(ch.ProfileAvatar)
	}
	if strings.TrimSpace(u.DisplayName) == "" && strings.TrimSpace(ch.ProfileName) != "" {
		_ = h.st.UpdateUser(ctx, u.ID, strings.TrimSpace(ch.ProfileName), u.Role, u.Active)
		u.DisplayName = strings.TrimSpace(ch.ProfileName)
	}
	return safeNextPath(ch.Redirect, "/profile"), nil
}

func isXProviderSlug(slug string) bool {
	switch strings.ToLower(strings.TrimSpace(slug)) {
	case "x", "xcom", "x.com", "twitter":
		return true
	default:
		return false
	}
}

func (h *Handler) finishExternalLogin(w http.ResponseWriter, r *http.Request, u *store.User, next string) {
	if !u.Active {
		h.renderError(w, r, http.StatusForbidden, "Account disabled", "Please contact an administrator.")
		return
	}
	if h.startSecondFactor(w, r, u, next) {
		return
	}

	ctx := r.Context()
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
	http.Redirect(w, r, safeNextPath(next, "/profile"), http.StatusFound)
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

func rpUserInfo(endpoint, accessToken string) (sub, email string, emailVerified bool, name, username, picture string, err error) {
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

	source := claims
	if dataObj, ok := claims["data"].(map[string]any); ok && len(dataObj) > 0 {
		source = dataObj
	}

	sub = stringClaim(source, "sub")
	if sub == "" {
		sub = stringClaim(source, "id")
	}
	if sub == "" {
		sub = stringClaim(source, "user_id")
	}
	if sub == "" {
		if n, ok := source["id"].(float64); ok {
			sub = strconv.FormatInt(int64(n), 10)
		}
	}
	if sub == "" {
		sub = stringClaim(claims, "sub")
	}

	email = stringClaim(source, "email")
	if email == "" {
		email = stringClaim(claims, "email")
	}
	if email == "" {
		email = stringClaim(source, "upn")
	}
	if email == "" {
		email = stringClaim(claims, "upn")
	}
	emailVerified = boolClaim(source, "email_verified") || boolClaim(claims, "email_verified")

	username = stringClaim(source, "preferred_username")
	if username == "" {
		username = stringClaim(source, "username")
	}
	if username == "" {
		username = stringClaim(source, "screen_name")
	}
	if username == "" {
		username = stringClaim(claims, "preferred_username")
	}
	if username == "" {
		username = stringClaim(claims, "username")
	}
	if username == "" {
		username = stringClaim(claims, "screen_name")
	}

	name = stringClaim(source, "name")
	if name == "" {
		name = username
	}
	if name == "" {
		name = stringClaim(claims, "name")
	}

	picture = stringClaim(source, "picture")
	if picture == "" {
		picture = stringClaim(source, "profile_image_url")
	}
	if picture == "" {
		picture = stringClaim(source, "profile_image_url_https")
	}
	if picture == "" {
		picture = stringClaim(source, "avatar_url")
	}
	if picture == "" {
		picture = stringClaim(claims, "picture")
	}
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
