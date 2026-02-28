package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"transmtf.com/oidc/internal/store"
)

var providerSlugRe = regexp.MustCompile(`^[a-z0-9-]+$`)

const (
	faviconPNG = "favicon.png"
	faviconJPG = "favicon.jpg"
	providerTypeOIDC   = "oidc"
	providerTypeOAuth2 = "oauth2"
)

func normalizeProviderType(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case providerTypeOAuth2:
		return providerTypeOAuth2
	default:
		return providerTypeOIDC
	}
}

func defaultProviderScopes(providerType string) []string {
	if providerType == providerTypeOAuth2 {
		return []string{"profile", "email"}
	}
	return []string{"openid", "email", "profile"}
}

func normalizeProviderEndpoints(providerType, issuerURL, authorizationURL, tokenURL, userinfoURL string) (string, string, string, string) {
	if providerType == providerTypeOAuth2 {
		return "", authorizationURL, tokenURL, userinfoURL
	}
	return issuerURL, "", "", ""
}

func validateProviderProtocolConfig(providerType, issuerURL, authorizationURL, tokenURL, userinfoURL string, scopes []string) string {
	switch providerType {
	case providerTypeOIDC:
		if issuerURL == "" {
			return "OIDC 提供商必须填写 Issuer URL"
		}
		if !isAllowedAbsoluteURL(issuerURL) {
			return "Issuer URL 必须是 HTTPS 地址，或本机调试地址"
		}
		if !containsScope(scopes, "openid") {
			return "OIDC scopes 必须包含 openid"
		}
	case providerTypeOAuth2:
		if authorizationURL == "" || tokenURL == "" || userinfoURL == "" {
			return "OAuth2 提供商必须填写 Authorization URL、Token URL 和 Userinfo URL"
		}
		if !isAllowedAbsoluteURL(authorizationURL) ||
			!isAllowedAbsoluteURL(tokenURL) ||
			!isAllowedAbsoluteURL(userinfoURL) {
			return "OAuth2 endpoints 必须是 HTTPS 地址，或本机调试地址"
		}
	default:
		return "不支持的 provider type"
	}
	return ""
}

func (h *Handler) AdminDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := h.pageData(r, "管理面板")
	d.Data = map[string]any{
		"Users":     h.st.CountUsers(ctx),
		"Clients":   h.st.CountClients(ctx),
		"Projects":  h.st.CountProjects(ctx),
		"Providers": h.st.CountOIDCProviders(ctx),
	}
	h.render(w, "admin_dashboard", d)
}

func (h *Handler) AdminUsers(w http.ResponseWriter, r *http.Request) {
	users, _ := h.st.ListUsers(r.Context())
	customRoles, _ := h.st.ListCustomRoles(r.Context())
	d := h.pageData(r, "用户管理")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = map[string]any{
		"Users":       users,
		"CustomRoles": customRoles,
	}
	h.render(w, "admin_users", d)
}

func (h *Handler) AdminUserCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	name := strings.TrimSpace(r.FormValue("display_name"))
	role := r.FormValue("role")
	if role == "" {
		role = "user"
	}
	requireChange := r.FormValue("require_password_change") == "1"

	ctx := r.Context()
	d := h.pageData(r, "用户管理")
	users, _ := h.st.ListUsers(ctx)
	customRoles, _ := h.st.ListCustomRoles(ctx)
	d.Data = map[string]any{"Users": users, "CustomRoles": customRoles}
	if role == "admin" && !h.isSystemAdminUser(h.currentUser(r)) {
		d.Flash = "仅系统管理员可以分配管理员角色"
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}
	u, err := h.st.CreateUser(ctx, email, password, name, role)
	if err != nil {
		d.Flash = "创建失败：" + err.Error()
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}
	if requireChange {
		if err := h.st.SetRequirePasswordChange(ctx, u.ID, true); err != nil {
			// 非致命错误：用户已创建，仅忽略强制改密标记写入失败。
			_ = err
		}
	}
	h.logAudit(ctx, h.currentUser(r), "create", "user", u.ID, u.Email, "", marshalJSON(u))
	http.Redirect(w, r, "/admin/users?flash="+url.QueryEscape("已创建用户："+email), http.StatusFound)
}

func (h *Handler) AdminUserUpdate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	id := r.PathValue("id")
	name := strings.TrimSpace(r.FormValue("display_name"))
	role := r.FormValue("role")
	active := r.FormValue("active") == "1"

	ctx := r.Context()
	d := h.pageData(r, "用户管理")
	users, _ := h.st.ListUsers(ctx)
	customRoles, _ := h.st.ListCustomRoles(ctx)
	d.Data = map[string]any{"Users": users, "CustomRoles": customRoles}

	cur := h.currentUser(r)
	// 保护系统管理员账户
	targetUser, err := h.st.GetUserByID(ctx, id)
	if err != nil {
		d.Flash = "用户不存在"
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}
	if targetUser.IsAdmin() && !h.isSystemAdminUser(cur) {
		d.Flash = "不能修改管理员账户"
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}
	if role == "admin" && !h.isSystemAdminUser(cur) {
		d.Flash = "仅系统管理员可以分配管理员角色"
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}
	if h.isSystemAdminUser(targetUser) {
		role = "admin"
		active = true
	}

	if err := h.st.UpdateUser(ctx, id, name, role, active); err != nil {
		d.Flash = "更新失败: " + err.Error()
		d.IsError = true
		h.render(w, "admin_users", d)
	} else {
		h.logAudit(ctx, cur, "update", "user", id, targetUser.Email,
			marshalJSON(targetUser),
			marshalJSON(map[string]any{"display_name": name, "role": role, "active": active}))
		http.Redirect(w, r, "/admin/users?flash=已更新", http.StatusFound)
	}
}

func (h *Handler) AdminUserDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	id := r.PathValue("id")
	cur := h.currentUser(r)
	ctx := r.Context()
	d := h.pageData(r, "用户管理")

	targetUser, err := h.st.GetUserByID(ctx, id)
	if err != nil {
		users, _ := h.st.ListUsers(ctx)
		customRoles, _ := h.st.ListCustomRoles(ctx)
		d.Data = map[string]any{"Users": users, "CustomRoles": customRoles}
		d.Flash = "用户不存在"
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}
	if targetUser.IsAdmin() && !h.isSystemAdminUser(cur) {
		users, _ := h.st.ListUsers(ctx)
		customRoles, _ := h.st.ListCustomRoles(ctx)
		d.Data = map[string]any{"Users": users, "CustomRoles": customRoles}
		d.Flash = "不能修改管理员账户"
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}

	if cur != nil && cur.ID == id {
		users, _ := h.st.ListUsers(ctx)
		customRoles, _ := h.st.ListCustomRoles(ctx)
		d.Data = map[string]any{"Users": users, "CustomRoles": customRoles}
		d.Flash = "不能删除当前登录账户"
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}

	if err := h.st.DeleteUser(ctx, id); err != nil {
		users, _ := h.st.ListUsers(ctx)
		customRoles, _ := h.st.ListCustomRoles(ctx)
		d.Data = map[string]any{"Users": users, "CustomRoles": customRoles}
		d.Flash = "删除失败：" + err.Error()
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}

	h.logAudit(ctx, cur, "delete", "user", id, targetUser.Email, marshalJSON(targetUser), "")
	http.Redirect(w, r, "/admin/users?flash=已删除", http.StatusFound)
}

func (h *Handler) AdminUserDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	u, err := h.st.GetUserByID(ctx, id)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, "用户不存在", id)
		return
	}
	// 非系统管理员不能查看管理员账户的详情（含 session/token/passkey）。
	cur := h.currentUser(r)
	if u.IsAdmin() && !h.isSystemAdminUser(cur) {
		h.renderError(w, r, http.StatusForbidden, "访问被拒绝", "只有系统管理员可以查看管理员账户详情")
		return
	}
	identities, _ := h.st.GetUserIdentitiesByUserID(ctx, id)
	sessions, _ := h.st.GetSessionsByUserID(ctx, id)
	accessTokens, _ := h.st.GetAccessTokensByUserID(ctx, id)
	refreshTokens, _ := h.st.GetRefreshTokensByUserID(ctx, id)
	passkeys, _ := h.st.GetPasskeyCredentialsByUserID(ctx, id)
	customRoles, _ := h.st.ListCustomRoles(ctx)
	userGroups, _ := h.st.GetUserGroups(ctx, id)
	allGroups, _ := h.st.ListUserGroups(ctx)
	groupSet := make(map[string]struct{}, len(userGroups))
	for _, g := range userGroups {
		groupSet[g.ID] = struct{}{}
	}
	availableGroups := make([]*store.UserGroup, 0, len(allGroups))
	for _, g := range allGroups {
		if _, exists := groupSet[g.ID]; !exists {
			availableGroups = append(availableGroups, g)
		}
	}

	d := h.pageData(r, "用户详情")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = map[string]any{
		"User":              u,
		"Identities":        identities,
		"Sessions":          sessions,
		"AccessTokens":      accessTokens,
		"RefreshTokens":     refreshTokens,
		"Passkeys":          passkeys,
		"CustomRoles":       customRoles,
		"UserGroups":        userGroups,
		"AllGroups":         allGroups,
		"AvailableGroups":   availableGroups,
		"CanManageGroups":   h.userHasPermission(ctx, h.currentUser(r), "manage_groups"),
		"IsSystemAdmin":     h.isSystemAdminUser(u),
		"CurrentIsSysAdmin": h.isSystemAdminUser(h.currentUser(r)),
	}
	h.render(w, "admin_user_detail", d)
}

func (h *Handler) AdminUserResetPassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	id := r.PathValue("id")
	newPass := r.FormValue("new_password")
	requireChange := r.FormValue("require_password_change") == "1"
	ctx := r.Context()

	targetUser, err := h.st.GetUserByID(ctx, id)
	if err != nil {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=用户不存在", http.StatusFound)
		return
	}
	// 仅系统管理员可修改其他管理员的密码。
	cur := h.currentUser(r)
	if targetUser.IsAdmin() && !h.isSystemAdminUser(cur) {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=不能修改管理员账户", http.StatusFound)
		return
	}

	if len(newPass) < 8 {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=密码至少需要8位", http.StatusFound)
		return
	}
	if err := h.st.UpdatePassword(ctx, id, newPass); err != nil {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=密码重置失败", http.StatusFound)
		return
	}
	if requireChange {
		_ = h.st.SetRequirePasswordChange(ctx, id, true)
	}
	go h.sendPasswordResetEmail(context.Background(), targetUser.Email, targetUser.DisplayName, newPass)
	h.logAudit(ctx, h.currentUser(r), "update", "user", id, targetUser.Email,
		marshalJSON(map[string]string{"action": "reset_password"}), "")
	http.Redirect(w, r, "/admin/users/"+id+"?flash=密码已重置", http.StatusFound)
}

func (h *Handler) AdminUserDisable2FA(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()

	targetUser, err := h.st.GetUserByID(ctx, id)
	if err != nil {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=用户不存在", http.StatusFound)
		return
	}
	cur := h.currentUser(r)
	if targetUser.IsAdmin() && !h.isSystemAdminUser(cur) {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=不能修改管理员账户", http.StatusFound)
		return
	}

	if err := h.st.DisableTOTP(ctx, id); err != nil {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=关闭双重验证失败", http.StatusFound)
		return
	}
	h.logAudit(ctx, h.currentUser(r), "update", "user", id, targetUser.Email,
		marshalJSON(map[string]string{"action": "disable_2fa"}), "")
	http.Redirect(w, r, "/admin/users/"+id+"?flash=双重验证已关闭", http.StatusFound)
}

func (h *Handler) AdminUserRevokeSession(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	userID := r.PathValue("id")
	sessID := r.PathValue("sid")
	targetUser, err := h.st.GetUserByID(r.Context(), userID)
	if err != nil {
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=用户不存在", http.StatusFound)
		return
	}
	if targetUser.IsAdmin() && !h.isSystemAdminUser(h.currentUser(r)) {
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=不能修改管理员账户", http.StatusFound)
		return
	}
	if err := h.st.DeleteSessionByIDAndUserID(r.Context(), sessID, userID); err != nil {
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=会话不存在或已失效", http.StatusFound)
		return
	}
	h.logAudit(r.Context(), h.currentUser(r), "update", "user", userID, targetUser.Email,
		marshalJSON(map[string]string{"action": "revoke_session", "session_id": sessID}), "")
	http.Redirect(w, r, "/admin/users/"+userID+"?flash=会话已撤销", http.StatusFound)
}

func (h *Handler) AdminUserRevokeToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	userID := r.PathValue("id")
	tokenID := r.PathValue("tid")
	tokenType := r.FormValue("type")
	ctx := r.Context()
	targetUser, err := h.st.GetUserByID(ctx, userID)
	if err != nil {
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=用户不存在", http.StatusFound)
		return
	}
	if targetUser.IsAdmin() && !h.isSystemAdminUser(h.currentUser(r)) {
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=不能修改管理员账户", http.StatusFound)
		return
	}
	if tokenType == "refresh" {
		if err := h.st.RevokeRefreshTokenByIDAndUserID(ctx, tokenID, userID); err != nil {
			http.Redirect(w, r, "/admin/users/"+userID+"?flash=令牌不存在或已失效", http.StatusFound)
			return
		}
	} else {
		if err := h.st.RevokeAccessTokenByIDAndUserID(ctx, tokenID, userID); err != nil {
			http.Redirect(w, r, "/admin/users/"+userID+"?flash=令牌不存在或已失效", http.StatusFound)
			return
		}
	}
	h.logAudit(ctx, h.currentUser(r), "update", "user", userID, targetUser.Email,
		marshalJSON(map[string]string{"action": "revoke_token", "token_id": tokenID, "type": tokenType}), "")
	http.Redirect(w, r, "/admin/users/"+userID+"?flash=令牌已撤销", http.StatusFound)
}

// allPermissions 定义了自定义角色可用的全部权限。
var allPermissions = []map[string]string{
	{"name": "manage_projects", "label": "管理项目", "desc": "创建、更新和删除项目"},
	{"name": "manage_clients", "label": "管理应用", "desc": "管理授权登录应用"},
	{"name": "manage_announcements", "label": "管理公告", "desc": "编辑应用公告"},
	{"name": "manage_users", "label": "管理用户", "desc": "查看和管理用户账户"},
	{"name": "manage_groups", "label": "管理分组", "desc": "创建并管理用户分组"},
	{"name": "manage_providers", "label": "管理登录方式", "desc": "配置外部身份提供商"},
	{"name": "manage_roles", "label": "管理角色", "desc": "创建并编辑自定义角色"},
	{"name": "manage_settings", "label": "管理设置", "desc": "编辑全站设置"},
}

func (h *Handler) AdminRoles(w http.ResponseWriter, r *http.Request) {
	roles, _ := h.st.ListCustomRoles(r.Context())
	d := h.pageData(r, "角色管理")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = map[string]any{
		"Roles":       roles,
		"Permissions": allPermissions,
	}
	h.render(w, "admin_roles", d)
}

func (h *Handler) AdminRoleCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	name := strings.TrimSpace(strings.ToLower(r.FormValue("name")))
	label := strings.TrimSpace(r.FormValue("label"))
	permissions := r.Form["permissions"] // multi-value checkbox
	ctx := r.Context()
	d := h.pageData(r, "角色管理")
	roles, _ := h.st.ListCustomRoles(ctx)
	d.Data = map[string]any{
		"Roles":       roles,
		"Permissions": allPermissions,
	}
	if name == "" {
		d.Flash = "角色名称不能为空"
		d.IsError = true
		h.render(w, "admin_roles", d)
		return
	}
	if err := h.st.CreateCustomRole(ctx, name, label, permissions); err != nil {
		d.Flash = "创建失败：" + err.Error()
		d.IsError = true
		h.render(w, "admin_roles", d)
		return
	}
	if r2, _ := h.st.GetCustomRole(ctx, name); r2 != nil {
		h.logAudit(ctx, h.currentUser(r), "create", "role", r2.Name, r2.Label, "", marshalJSON(r2))
	}
	http.Redirect(w, r, "/admin/roles?flash=角色已创建", http.StatusFound)
}

func (h *Handler) AdminRoleDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	name := r.PathValue("name")
	existing, _ := h.st.GetCustomRole(r.Context(), name)
	if err := h.st.DeleteCustomRole(r.Context(), name); err != nil {
		http.Redirect(w, r, "/admin/roles?flash=删除失败："+err.Error(), http.StatusFound)
		return
	}
	if existing != nil {
		h.logAudit(r.Context(), h.currentUser(r), "delete", "role", existing.Name, existing.Label, marshalJSON(existing), "")
	}
	http.Redirect(w, r, "/admin/roles", http.StatusFound)
}

func (h *Handler) AdminClients(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	allClients, _ := h.st.ListClients(ctx)
	cur := h.currentUser(r)
	var clients []*store.OAuthClient
	for _, c := range allClients {
		if h.canManageClient(ctx, cur, c) {
			clients = append(clients, c)
		}
	}
	d := h.pageData(r, "应用管理")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = map[string]any{"Clients": clients}
	h.render(w, "admin_clients", d)
}

func (h *Handler) AdminClientCreatePage(w http.ResponseWriter, r *http.Request) {
	d := h.pageData(r, "创建应用")
	h.render(w, "admin_client_create", d)
}

func (h *Handler) AdminClientCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	desc := strings.TrimSpace(r.FormValue("description"))
	urisRaw := r.FormValue("redirect_uris")
	scopesRaw := r.FormValue("scopes")

	var uris []string
	for _, l := range strings.Split(urisRaw, "\n") {
		if u := strings.TrimSpace(l); u != "" {
			uris = append(uris, u)
		}
	}
	scopes := normalizeScopes(strings.Fields(scopesRaw))
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	ctx := r.Context()
	d := h.pageData(r, "创建应用")

	if name == "" {
		d.Flash = "应用名称不能为空"
		d.IsError = true
		h.render(w, "admin_client_create", d)
		return
	}
	if len(uris) == 0 {
		d.Flash = "至少需要一个回调地址"
		d.IsError = true
		h.render(w, "admin_client_create", d)
		return
	}
	for _, u := range uris {
		if !isAllowedAbsoluteURL(u) {
			d.Flash = "回调地址无效：" + u
			d.IsError = true
			h.render(w, "admin_client_create", d)
			return
		}
	}

	clientID, secret, err := h.st.CreateClient(ctx, name, desc, uris, scopes)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			d.Flash = "应用名称已存在，请换一个名称"
		} else {
			d.Flash = "创建失败：" + err.Error()
		}
		d.IsError = true
		h.render(w, "admin_client_create", d)
		return
	}

	// Fetch the created client to get its internal UUID for linking.
	newClient, _ := h.st.GetClientByClientID(ctx, clientID)
	internalID := ""
	if newClient != nil {
		internalID = newClient.ID
		h.logAudit(ctx, h.currentUser(r), "create", "client", internalID, name, "", marshalJSON(newClient))
	}

	ticket, tErr := h.issueOneTimeViewTicket(ctx, oneTimeClientCreatedView{
		NewClientID:   clientID,
		NewSecret:     secret,
		Name:          name,
		NewInternalID: internalID,
	})
	if tErr != nil {
		d.Flash = "创建成功，但结果页面准备失败：" + tErr.Error()
		d.IsError = true
		h.render(w, "admin_client_create", d)
		return
	}
	http.Redirect(w, r, "/admin/clients/created-result?ticket="+url.QueryEscape(ticket)+"&id="+url.QueryEscape(internalID), http.StatusFound)
}

func (h *Handler) AdminClientCreatedResult(w http.ResponseWriter, r *http.Request) {
	ticket := strings.TrimSpace(r.URL.Query().Get("ticket"))
	if ticket == "" {
		http.Redirect(w, r, "/admin/clients/new?flash=结果已过期", http.StatusFound)
		return
	}
	clientInternalID := r.URL.Query().Get("id")
	ctx := r.Context()
	// Permission check BEFORE consuming ticket.
	if clientInternalID != "" {
		if client, err := h.st.GetClientByID(ctx, clientInternalID); err == nil {
			if !h.canManageClient(ctx, h.currentUser(r), client) {
				h.renderError(w, r, http.StatusForbidden, "访问被拒绝", "您没有权限查看此应用密钥")
				return
			}
		}
	}
	var payload oneTimeClientCreatedView
	if err := h.consumeOneTimeViewTicket(ctx, ticket, &payload); err != nil {
		http.Redirect(w, r, "/admin/clients/new?flash=结果已过期", http.StatusFound)
		return
	}

	d := h.pageData(r, "应用已创建")
	d.Data = map[string]any{
		"NewClientID":   payload.NewClientID,
		"NewSecret":     payload.NewSecret,
		"Name":          payload.Name,
		"NewInternalID": payload.NewInternalID,
	}
	h.render(w, "admin_client_created", d)
}

func (h *Handler) AdminClientDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	client, err := h.st.GetClientByID(ctx, id)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, "应用不存在", id)
		return
	}
	if !h.canManageClient(ctx, h.currentUser(r), client) {
		h.renderError(w, r, http.StatusForbidden, "访问被拒绝", "您没有权限管理此应用")
		return
	}
	ann := h.st.GetClientAnnouncement(ctx, client.ClientID)
	allGroups, _ := h.st.ListUserGroups(ctx)
	d := h.pageData(r, client.Name)
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = map[string]any{
		"Client":       client,
		"Announcement": ann,
		"AllGroups":    allGroups,
		"CanManage":    h.canManageClient(ctx, h.currentUser(r), client),
	}
	h.render(w, "admin_client_detail", d)
}

func (h *Handler) AdminClientUpdate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	id := r.PathValue("id")
	name := strings.TrimSpace(r.FormValue("name"))
	desc := strings.TrimSpace(r.FormValue("description"))
	urisRaw := r.FormValue("redirect_uris")
	scopesRaw := r.FormValue("scopes")
	baseAccess := strings.ToLower(strings.TrimSpace(r.FormValue("base_access")))
	allowedGroupsRaw := r.FormValue("allowed_groups")

	ctx := r.Context()
	// Check per-app manager permission.
	client0, err := h.st.GetClientByID(ctx, id)
	if err != nil {
		http.Redirect(w, r, "/admin/clients?flash=应用不存在", http.StatusFound)
		return
	}
	if !h.canManageClient(ctx, h.currentUser(r), client0) {
		h.renderError(w, r, http.StatusForbidden, "访问被拒绝", "您没有权限管理此应用")
		return
	}

	var uris []string
	for _, l := range strings.Split(urisRaw, "\n") {
		if u := strings.TrimSpace(l); u != "" {
			uris = append(uris, u)
		}
	}
	scopes := normalizeScopes(strings.Fields(scopesRaw))
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	if baseAccess == "" {
		baseAccess = "user"
	}
	switch baseAccess {
	case "legacy", "user", "member", "admin", "none":
	default:
		http.Redirect(w, r, "/admin/clients/"+id+"?flash=基础访问策略无效", http.StatusFound)
		return
	}
	allowedGroupsSet := map[string]bool{}
	var allowedGroups []string
	for _, g := range strings.Fields(strings.ToLower(allowedGroupsRaw)) {
		if g == "" || allowedGroupsSet[g] {
			continue
		}
		allowedGroupsSet[g] = true
		allowedGroups = append(allowedGroups, g)
	}

	if name == "" {
		http.Redirect(w, r, "/admin/clients/"+id+"?flash=名称不能为空", http.StatusFound)
		return
	}
	// Validate custom groups exist to avoid silent misconfiguration.
	groupSet := map[string]bool{}
	groups, err := h.st.ListUserGroups(ctx)
	if err != nil {
		http.Redirect(w, r, "/admin/clients/"+id+"?flash=分组查询失败", http.StatusFound)
		return
	}
	for _, g := range groups {
		groupSet[strings.ToLower(strings.TrimSpace(g.Name))] = true
	}
	for _, g := range allowedGroups {
		switch g {
		case "admin", "member", "user":
			continue
		default:
			if !groupSet[g] {
				http.Redirect(w, r, "/admin/clients/"+id+"?flash=未知分组："+g, http.StatusFound)
				return
			}
		}
	}
	if err := h.st.UpdateClient(ctx, id, name, desc, uris, scopes, baseAccess, allowedGroups); err != nil {
		msg := "更新失败"
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			msg = "应用名称已存在"
		}
		http.Redirect(w, r, "/admin/clients/"+id+"?flash="+msg, http.StatusFound)
		return
	}
	// client0 captured before update contains the before_state.
	h.logAudit(ctx, h.currentUser(r), "update", "client", id, client0.Name,
		marshalJSON(client0), marshalJSON(map[string]any{"name": name, "description": desc, "base_access": baseAccess, "allowed_groups": allowedGroups}))
	http.Redirect(w, r, "/admin/clients/"+id+"?flash=已更新", http.StatusFound)
}

func (h *Handler) AdminClientResetSecret(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	id := r.PathValue("id")
	ctx := r.Context()
	client, err := h.st.GetClientByID(ctx, id)
	if err != nil {
		http.Redirect(w, r, "/admin/clients?flash=应用不存在", http.StatusFound)
		return
	}
	if !h.canManageClient(ctx, h.currentUser(r), client) {
		h.renderError(w, r, http.StatusForbidden, "访问被拒绝", "您没有权限管理此应用")
		return
	}
	newSecret, err := h.st.ResetClientSecret(ctx, id)
	if err != nil {
		http.Redirect(w, r, "/admin/clients/"+id+"?flash=重置失败", http.StatusFound)
		return
	}

	ticket, tErr := h.issueOneTimeViewTicket(ctx, oneTimeClientSecretView{
		ClientInternalID: id,
		NewSecret:        newSecret,
	})
	if tErr != nil {
		http.Redirect(w, r, "/admin/clients/"+id+"?flash=重置成功但结果页面准备失败", http.StatusFound)
		return
	}
	h.logAudit(ctx, h.currentUser(r), "update", "client", id, client.Name,
		marshalJSON(map[string]string{"client_secret": "previous"}),
		marshalJSON(map[string]string{"client_secret": "reset"}))
	http.Redirect(w, r, "/admin/clients/"+id+"/secret?ticket="+url.QueryEscape(ticket), http.StatusFound)
}

func (h *Handler) AdminClientSecretResult(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ticket := strings.TrimSpace(r.URL.Query().Get("ticket"))
	if ticket == "" {
		http.Redirect(w, r, "/admin/clients/"+id+"?flash=结果已过期", http.StatusFound)
		return
	}

	ctx := r.Context()
	// Perform permission check BEFORE consuming (burning) the ticket,
	// so an unauthorized request does not invalidate it for the legitimate user.
	client, err := h.st.GetClientByID(ctx, id)
	if err != nil {
		http.Redirect(w, r, "/admin/clients?flash=应用不存在", http.StatusFound)
		return
	}
	if !h.canManageClient(ctx, h.currentUser(r), client) {
		h.renderError(w, r, http.StatusForbidden, "访问被拒绝", "您没有权限查看此应用的密钥")
		return
	}

	var payload oneTimeClientSecretView
	if err := h.consumeOneTimeViewTicket(ctx, ticket, &payload); err != nil {
		http.Redirect(w, r, "/admin/clients/"+id+"?flash=结果已过期", http.StatusFound)
		return
	}
	if payload.ClientInternalID != id {
		http.Redirect(w, r, "/admin/clients/"+id+"?flash=结果票据无效", http.StatusFound)
		return
	}

	d := h.pageData(r, "密钥已重置")
	d.Flash = "应用密钥已重置，请立即保存（仅显示一次）。"
	d.Data = map[string]any{
		"Client":    client,
		"NewSecret": payload.NewSecret,
	}
	h.render(w, "admin_client_secret", d)
}

func (h *Handler) AdminClientDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	id := r.PathValue("id")
	ctx := r.Context()
	d := h.pageData(r, "应用管理")
	existing, _ := h.st.GetClientByID(ctx, id)
	if err := h.st.DeleteClient(ctx, id); err != nil {
		d.Flash = "删除失败：" + err.Error()
		d.IsError = true
		clients, _ := h.st.ListClients(ctx)
		d.Data = map[string]any{"Clients": clients}
		h.render(w, "admin_clients", d)
		return
	}
	if existing != nil {
		h.logAudit(ctx, h.currentUser(r), "delete", "client", id, existing.Name, marshalJSON(existing), "")
	}
	http.Redirect(w, r, "/admin/clients?flash=已删除", http.StatusFound)
}

func (h *Handler) AdminAnnouncements(w http.ResponseWriter, r *http.Request) {
	clients, _ := h.st.ListClients(r.Context())
	cur := h.currentUser(r)
	type clientWithAnn struct {
		*store.OAuthClient
		Announcement string
	}
	var items []clientWithAnn
	for _, c := range clients {
		if !h.canManageClient(r.Context(), cur, c) {
			continue
		}
		items = append(items, clientWithAnn{
			OAuthClient:  c,
			Announcement: h.st.GetClientAnnouncement(r.Context(), c.ClientID),
		})
	}
	d := h.pageData(r, "应用公告")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = items
	h.render(w, "admin_announcements", d)
}

func (h *Handler) AdminAnnouncementSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	clientID := r.PathValue("clientid")
	content := r.FormValue("content")
	ctx := r.Context()
	client, err := h.st.GetClientByClientID(ctx, clientID)
	if err != nil {
		http.Redirect(w, r, "/admin/announcements?flash=应用不存在", http.StatusFound)
		return
	}
	// Verify the current user is authorized to manage this specific client.
	if !h.canManageClient(ctx, h.currentUser(r), client) {
		h.renderError(w, r, http.StatusForbidden, "访问被拒绝", "您没有权限管理此应用的公告")
		return
	}
	existingAnn := h.st.GetClientAnnouncement(ctx, clientID)
	if err := h.st.SetClientAnnouncement(ctx, clientID, content); err != nil {
		http.Redirect(w, r, "/admin/announcements?flash=保存失败", http.StatusFound)
		return
	}
	h.logAudit(ctx, h.currentUser(r), "update", "announcement", clientID, clientID,
		marshalJSON(map[string]string{"client_id": clientID, "content": existingAnn}),
		marshalJSON(map[string]string{"client_id": clientID, "content": content}))
	http.Redirect(w, r, "/admin/announcements?flash=公告已保存", http.StatusFound)
}

func (h *Handler) AdminSettingsUploadIcon(w http.ResponseWriter, r *http.Request) {
	// Limit upload size to 512 KB.
	r.Body = http.MaxBytesReader(w, r.Body, 512*1024)
	if err := r.ParseMultipartForm(512 * 1024); err != nil {
		http.Redirect(w, r, "/admin/settings?flash=文件过大（最大512KB）", http.StatusFound)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	file, _, err := r.FormFile("icon_file")
	if err != nil {
		http.Redirect(w, r, "/admin/settings?flash=未选择文件", http.StatusFound)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		http.Redirect(w, r, "/admin/settings?flash=读取文件失败", http.StatusFound)
		return
	}
	if len(data) == 0 {
		http.Redirect(w, r, "/admin/settings?flash=文件为空", http.StatusFound)
		return
	}
	mimeType := http.DetectContentType(data)
	fileName, ok := uploadedFaviconFileName(mimeType)
	if !ok {
		http.Redirect(w, r, "/admin/settings?flash=仅支持图片上传", http.StatusFound)
		return
	}
	fullPath := filepath.Join(".", fileName)
	if err := os.WriteFile(fullPath, data, 0o644); err != nil {
		http.Redirect(w, r, "/admin/settings?flash=保存图标失败", http.StatusFound)
		return
	}
	removeLegacyFavicons(fileName)

	ctx := r.Context()
	_ = h.st.SetSetting(ctx, "site_icon_url", "/"+fileName)

	http.Redirect(w, r, "/admin/settings?flash=图标已上传："+fileName, http.StatusFound)
}

func (h *Handler) AdminSettings(w http.ResponseWriter, r *http.Request) {
	cfg := h.st.GetAllSettings(r.Context())
	d := h.pageData(r, "站点设置")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = cfg
	h.render(w, "admin_settings", d)
}

func (h *Handler) AdminSettingsSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	ctx := r.Context()
	oldSettings := h.st.GetAllSettings(ctx)
	keys := []string{
		"site_name", "contact_email", "site_icon_url",
		"ann_zh", "ann_en",
		"tos_content", "privacy_content",
		"email_provider",
		"smtp_host", "smtp_port", "smtp_user", "smtp_from",
		"resend_from",
		"email_tpl_welcome", "email_tpl_password_reset",
	}
	newSettings := make(map[string]string, len(keys))
	for _, k := range keys {
		newSettings[k] = r.FormValue(k)
		_ = h.st.SetSetting(ctx, k, r.FormValue(k))
	}
	// 密码/密钥字段：只有提供了新值才覆盖。
	for _, k := range []string{"smtp_pass", "resend_api_key"} {
		if v := r.FormValue(k); v != "" {
			newSettings[k] = v
			_ = h.st.SetSetting(ctx, k, v)
		}
	}
	h.logAudit(ctx, h.currentUser(r), "update", "setting", "site", "站点设置",
		marshalJSON(oldSettings), marshalJSON(newSettings))
	http.Redirect(w, r, "/admin/settings?flash=设置已保存", http.StatusFound)
}

func (h *Handler) AdminProviders(w http.ResponseWriter, r *http.Request) {
	providers, _ := h.st.ListOIDCProviders(r.Context())
	for _, p := range providers {
		p.ProviderType = normalizeProviderType(p.ProviderType)
	}
	d := h.pageData(r, "登录方式")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = providers
	h.render(w, "admin_providers", d)
}

func (h *Handler) AdminProviderCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	slug := strings.TrimSpace(r.FormValue("slug"))
	providerType := normalizeProviderType(r.FormValue("provider_type"))
	icon := strings.TrimSpace(r.FormValue("icon"))
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := r.FormValue("client_secret")
	issuerURL := strings.TrimSpace(r.FormValue("issuer_url"))
	authorizationURL := strings.TrimSpace(r.FormValue("authorization_url"))
	tokenURL := strings.TrimSpace(r.FormValue("token_url"))
	userinfoURL := strings.TrimSpace(r.FormValue("userinfo_url"))
	scopes := normalizeScopes(strings.Fields(strings.TrimSpace(r.FormValue("scopes"))))
	autoRegister := false
	if len(scopes) == 0 {
		scopes = defaultProviderScopes(providerType)
	}

	renderErr := func(msg string) {
		d := h.pageData(r, "登录方式")
		providers, _ := h.st.ListOIDCProviders(r.Context())
		d.Data = providers
		d.Flash = msg
		d.IsError = true
		h.render(w, "admin_providers", d)
	}

	if name == "" || slug == "" || clientID == "" || clientSecret == "" {
		renderErr("请完整填写登录方式信息")
		return
	}
	if !providerSlugRe.MatchString(slug) {
		renderErr("路径标识只能包含小写字母、数字和连字符")
		return
	}
	if msg := validateProviderProtocolConfig(providerType, issuerURL, authorizationURL, tokenURL, userinfoURL, scopes); msg != "" {
		renderErr(msg)
		return
	}
	issuerURL, authorizationURL, tokenURL, userinfoURL = normalizeProviderEndpoints(
		providerType, issuerURL, authorizationURL, tokenURL, userinfoURL)

	ctx := r.Context()
	if err := h.st.CreateOIDCProvider(ctx, name, slug, providerType, icon, clientID, clientSecret, issuerURL, authorizationURL, tokenURL, userinfoURL, strings.Join(scopes, " "), autoRegister); err != nil {
		renderErr("创建失败：" + err.Error())
		return
	}
	if p, _ := h.st.GetOIDCProviderBySlug(ctx, slug); p != nil {
		h.logAudit(ctx, h.currentUser(r), "create", "provider", p.ID, p.Name, "", marshalJSON(p))
	}
	http.Redirect(w, r, "/admin/providers?flash=登录方式已添加", http.StatusFound)
}

func (h *Handler) AdminProviderToggle(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()
	p, err := h.st.GetOIDCProviderByID(ctx, id)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, "未找到", id)
		return
	}
	if err := h.st.UpdateOIDCProvider(ctx, p.ID, p.Name, normalizeProviderType(p.ProviderType), p.Icon, p.ClientID, p.ClientSecret, p.IssuerURL, p.AuthorizationURL, p.TokenURL, p.UserinfoURL, p.Scopes, !p.Enabled, p.AutoRegister); err != nil {
		http.Redirect(w, r, "/admin/providers?flash="+url.QueryEscape("操作失败："+err.Error()), http.StatusFound)
		return
	}
	h.logAudit(ctx, h.currentUser(r), "update", "provider", p.ID, p.Name,
		marshalJSON(map[string]any{"enabled": p.Enabled}),
		marshalJSON(map[string]any{"enabled": !p.Enabled}))
	http.Redirect(w, r, "/admin/providers", http.StatusFound)
}

func (h *Handler) AdminProviderDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()
	existing, _ := h.st.GetOIDCProviderByID(ctx, id)
	if err := h.st.DeleteOIDCProvider(ctx, id); err != nil {
		http.Redirect(w, r, "/admin/providers?flash="+url.QueryEscape("删除失败："+err.Error()), http.StatusFound)
		return
	}
	if existing != nil {
		h.logAudit(ctx, h.currentUser(r), "delete", "provider", id, existing.Name, marshalJSON(existing), "")
	}
	http.Redirect(w, r, "/admin/providers", http.StatusFound)
}

// 用户分组管理。

func (h *Handler) AdminGroups(w http.ResponseWriter, r *http.Request) {
	groups, _ := h.st.ListUserGroups(r.Context())
	d := h.pageData(r, "分组管理")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = groups
	h.render(w, "admin_groups", d)
}

func (h *Handler) AdminGroupCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	name := strings.TrimSpace(strings.ToLower(r.FormValue("name")))
	label := strings.TrimSpace(r.FormValue("label"))
	ctx := r.Context()

	renderErr := func(msg string) {
		groups, _ := h.st.ListUserGroups(ctx)
		d := h.pageData(r, "分组管理")
		d.Flash = msg
		d.IsError = true
		d.Data = groups
		h.render(w, "admin_groups", d)
	}

	if name == "" {
		renderErr("分组名称不能为空")
		return
	}
	if name == "admin" || name == "member" || name == "user" {
		renderErr("不能使用内置分组名称（管理员/成员/用户）")
		return
	}
	if err := h.st.CreateUserGroup(ctx, name, label); err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			renderErr("分组名称已存在")
		} else {
			renderErr("创建失败：" + err.Error())
		}
		return
	}
	// Fetch newly created group for audit.
	if grps, _ := h.st.ListUserGroups(ctx); len(grps) > 0 {
		for _, g := range grps {
			if g.Name == name {
				h.logAudit(ctx, h.currentUser(r), "create", "group", g.ID, g.Name, "", marshalJSON(g))
				break
			}
		}
	}
	http.Redirect(w, r, "/admin/groups?flash=分组已创建", http.StatusFound)
}

func (h *Handler) AdminGroupDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	g, err := h.st.GetUserGroupByID(ctx, id)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, "分组不存在", id)
		return
	}
	members, _ := h.st.GetGroupMembers(ctx, id)
	users, _ := h.st.ListUsers(ctx)
	d := h.pageData(r, g.Label+" 分组")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = map[string]any{
		"Group":   g,
		"Members": members,
		"Users":   users,
	}
	h.render(w, "admin_group_detail", d)
}

func (h *Handler) AdminGroupDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	id := r.PathValue("id")
	existing, _ := h.st.GetUserGroupByID(r.Context(), id)
	if err := h.st.DeleteUserGroup(r.Context(), id); err != nil {
		http.Redirect(w, r, "/admin/groups?flash=删除失败："+err.Error(), http.StatusFound)
		return
	}
	if existing != nil {
		h.logAudit(r.Context(), h.currentUser(r), "delete", "group", id, existing.Name, marshalJSON(existing), "")
	}
	http.Redirect(w, r, "/admin/groups?flash=分组已删除", http.StatusFound)
}

func (h *Handler) AdminGroupAddMember(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	groupID := r.PathValue("id")
	userID := r.FormValue("user_id")
	if err := h.st.AddUserToGroup(r.Context(), userID, groupID); err != nil {
		http.Redirect(w, r, "/admin/groups/"+groupID+"?flash=添加失败："+err.Error(), http.StatusFound)
		return
	}
	h.logAudit(r.Context(), h.currentUser(r), "update", "group", groupID, groupID,
		"", marshalJSON(map[string]string{"user_id": userID, "action": "add_member"}))
	http.Redirect(w, r, "/admin/groups/"+groupID+"?flash=成员已添加", http.StatusFound)
}

func (h *Handler) AdminGroupRemoveMember(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	groupID := r.PathValue("id")
	userID := r.PathValue("uid")
	if err := h.st.RemoveUserFromGroup(r.Context(), userID, groupID); err != nil {
		http.Redirect(w, r, "/admin/groups/"+groupID+"?flash=移除失败："+err.Error(), http.StatusFound)
		return
	}
	h.logAudit(r.Context(), h.currentUser(r), "update", "group", groupID, groupID,
		marshalJSON(map[string]string{"user_id": userID}), marshalJSON(map[string]string{"action": "remove_member"}))
	http.Redirect(w, r, "/admin/groups/"+groupID+"?flash=成员已移除", http.StatusFound)
}

// AdminUserGroupAdd：在用户详情页将用户加入分组。
func (h *Handler) AdminUserGroupAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	userID := r.PathValue("id")
	groupID := strings.TrimSpace(r.FormValue("group_id"))
	if groupID == "" {
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=请选择分组", http.StatusFound)
		return
	}
	if _, err := h.st.GetUserGroupByID(r.Context(), groupID); err != nil {
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=分组不存在", http.StatusFound)
		return
	}
	if err := h.st.AddUserToGroup(r.Context(), userID, groupID); err != nil {
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=添加分组失败："+err.Error(), http.StatusFound)
		return
	}
	h.logAudit(r.Context(), h.currentUser(r), "update", "user", userID, userID,
		"", marshalJSON(map[string]string{"group_id": groupID, "action": "add_to_group"}))
	http.Redirect(w, r, "/admin/users/"+userID+"?flash=已加入分组", http.StatusFound)
}

// AdminUserGroupRemove：在用户详情页将用户移出分组。
func (h *Handler) AdminUserGroupRemove(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	userID := r.PathValue("id")
	groupID := r.PathValue("gid")
	if err := h.st.RemoveUserFromGroup(r.Context(), userID, groupID); err != nil {
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=移除分组失败："+err.Error(), http.StatusFound)
		return
	}
	h.logAudit(r.Context(), h.currentUser(r), "update", "user", userID, userID,
		marshalJSON(map[string]string{"group_id": groupID}), marshalJSON(map[string]string{"action": "remove_from_group"}))
	http.Redirect(w, r, "/admin/users/"+userID+"?flash=已移出分组", http.StatusFound)
}

func uploadedFaviconFileName(mimeType string) (string, bool) {
	switch mimeType {
	case "image/png":
		return faviconPNG, true
	case "image/jpeg":
		return faviconJPG, true
	default:
		return "", false
	}
}

func removeLegacyFavicons(keep string) {
	for _, name := range []string{faviconPNG, faviconJPG} {
		if name == keep {
			continue
		}
		_ = os.Remove(filepath.Join(".", name))
	}
}

func (h *Handler) SiteFaviconFile(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name != faviconPNG && name != faviconJPG {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(".", name)
	if _, err := os.Stat(path); err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFile(w, r, path)
}

// AdminSiteIcon 提供设置中保存的站点图标（用于站点清单与邮件头像）。
func (h *Handler) AdminSiteIcon(w http.ResponseWriter, r *http.Request) {
	iconURL := h.st.GetSetting(r.Context(), "site_icon_url")
	if iconURL == "" {
		http.NotFound(w, r)
		return
	}
	// 数据地址：直接解码并返回。
	const dataPrefix = "data:"
	if strings.HasPrefix(iconURL, dataPrefix) {
		// 格式：data:<mime>;base64,<data>
		rest := iconURL[len(dataPrefix):]
		semi := strings.Index(rest, ";")
		if semi < 0 {
			http.NotFound(w, r)
			return
		}
		mime := rest[:semi]
		b64part := rest[semi+1:]
		if !strings.HasPrefix(b64part, "base64,") {
			http.NotFound(w, r)
			return
		}
		decoded, err := base64.StdEncoding.DecodeString(b64part[7:])
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", mime)
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(decoded)
		return
	}
	// 普通地址：直接重定向。
	http.Redirect(w, r, iconURL, http.StatusFound)
}

// AdminVerifyEmail：管理员手动标记用户邮箱为已验证。
func (h *Handler) AdminVerifyEmail(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()
	targetUser, err := h.st.GetUserByID(ctx, id)
	if err != nil {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=用户不存在", http.StatusFound)
		return
	}
	cur := h.currentUser(r)
	if targetUser.IsAdmin() && !h.isSystemAdminUser(cur) {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=不能修改管理员账户", http.StatusFound)
		return
	}
	if err := h.st.SetEmailVerified(ctx, id, true); err != nil {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=邮箱验证失败", http.StatusFound)
		return
	}
	h.logAudit(ctx, h.currentUser(r), "update", "user", id, targetUser.Email,
		marshalJSON(map[string]bool{"email_verified": targetUser.EmailVerified}),
		marshalJSON(map[string]bool{"email_verified": true}))
	http.Redirect(w, r, "/admin/users/"+id+"?flash=邮箱已验证", http.StatusFound)
}

// AdminUnverifyEmail：管理员将用户邮箱标记为未验证。
func (h *Handler) AdminUnverifyEmail(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()
	targetUser, err := h.st.GetUserByID(ctx, id)
	if err != nil {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=用户不存在", http.StatusFound)
		return
	}
	cur := h.currentUser(r)
	if targetUser.IsAdmin() && !h.isSystemAdminUser(cur) {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=不能修改管理员账户", http.StatusFound)
		return
	}
	if err := h.st.SetEmailVerified(ctx, id, false); err != nil {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=取消邮箱验证失败", http.StatusFound)
		return
	}
	h.logAudit(ctx, h.currentUser(r), "update", "user", id, targetUser.Email,
		marshalJSON(map[string]bool{"email_verified": targetUser.EmailVerified}),
		marshalJSON(map[string]bool{"email_verified": false}))
	http.Redirect(w, r, "/admin/users/"+id+"?flash=已设为未验证", http.StatusFound)
}

// AdminProviderEditPage：显示现有登录方式的编辑页面。
func (h *Handler) AdminProviderEditPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	p, err := h.st.GetOIDCProviderByID(ctx, id)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, "提供商不存在", id)
		return
	}
	p.ProviderType = normalizeProviderType(p.ProviderType)
	d := h.pageData(r, "编辑登录方式")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = p
	h.render(w, "admin_provider_detail", d)
}

// AdminProviderEdit：处理更新登录方式的提交。
func (h *Handler) AdminProviderEdit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()
	p, err := h.st.GetOIDCProviderByID(ctx, id)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, "提供商不存在", id)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	providerType := normalizeProviderType(r.FormValue("provider_type"))
	icon := strings.TrimSpace(r.FormValue("icon"))
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := r.FormValue("client_secret")
	issuerURL := strings.TrimSpace(r.FormValue("issuer_url"))
	authorizationURL := strings.TrimSpace(r.FormValue("authorization_url"))
	tokenURL := strings.TrimSpace(r.FormValue("token_url"))
	userinfoURL := strings.TrimSpace(r.FormValue("userinfo_url"))
	scopes := normalizeScopes(strings.Fields(strings.TrimSpace(r.FormValue("scopes"))))
	autoRegister := p.AutoRegister

	if len(scopes) == 0 {
		scopes = defaultProviderScopes(providerType)
	}

	renderErr := func(msg string) {
		d := h.pageData(r, "编辑登录方式")
		d.Data = p
		d.Flash = msg
		d.IsError = true
		h.render(w, "admin_provider_detail", d)
	}

	if name == "" {
		renderErr("名称不能为空")
		return
	}
	if msg := validateProviderProtocolConfig(providerType, issuerURL, authorizationURL, tokenURL, userinfoURL, scopes); msg != "" {
		renderErr(msg)
		return
	}
	issuerURL, authorizationURL, tokenURL, userinfoURL = normalizeProviderEndpoints(
		providerType, issuerURL, authorizationURL, tokenURL, userinfoURL)

	// 若密钥留空，保持原有值。
	if clientSecret == "" {
		clientSecret = p.ClientSecret
	}
	if clientID == "" {
		clientID = p.ClientID
	}

	if err := h.st.UpdateOIDCProvider(ctx, p.ID, name, providerType, icon, clientID, clientSecret, issuerURL, authorizationURL, tokenURL, userinfoURL, strings.Join(scopes, " "), p.Enabled, autoRegister); err != nil {
		renderErr("更新失败: " + err.Error())
		return
	}
	h.logAudit(ctx, h.currentUser(r), "update", "provider", p.ID, p.Name, marshalJSON(p),
		marshalJSON(map[string]any{"name": name, "provider_type": providerType, "enabled": p.Enabled}))
	http.Redirect(w, r, "/admin/providers/"+id+"/edit?flash=已更新", http.StatusFound)
}

type oneTimeClientCreatedView struct {
	NewClientID   string `json:"new_client_id"`
	NewSecret     string `json:"new_secret"`
	Name          string `json:"name"`
	NewInternalID string `json:"new_internal_id"`
}

type oneTimeClientSecretView struct {
	ClientInternalID string `json:"client_internal_id"`
	NewSecret        string `json:"new_secret"`
}

func (h *Handler) issueOneTimeViewTicket(ctx context.Context, v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	ticket := "view_" + uuid.New().String()
	if err := h.st.CreateWebAuthnSession(ctx, ticket, string(b)); err != nil {
		return "", err
	}
	return ticket, nil
}

func (h *Handler) consumeOneTimeViewTicket(ctx context.Context, ticket string, out any) error {
	raw, err := h.st.GetAndDeleteWebAuthnSession(ctx, ticket)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(raw), out)
}

// ─── Audit Log ───────────────────────────────────────────────────────────────

// logAudit records an auditable operation. Errors are only logged; they never
// interrupt the calling request.
func (h *Handler) logAudit(ctx context.Context, u *store.User, action, entityType, entityID, entityName, before, after string) {
	if u == nil {
		return
	}
	al := &store.AuditLog{
		OperatorID:   u.ID,
		OperatorName: u.DisplayName,
		OperatorRole: u.Role,
		Action:       action,
		EntityType:   entityType,
		EntityID:     entityID,
		EntityName:   entityName,
		BeforeState:  before,
		AfterState:   after,
	}
	if err := h.st.CreateAuditLog(ctx, al); err != nil {
		log.Printf("audit log write failed: %v", err)
	}
}

// marshalJSON is a convenience wrapper that returns "" on error.
func marshalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func (h *Handler) AdminAuditLogs(w http.ResponseWriter, r *http.Request) {
	logs, _ := h.st.ListAuditLogs(r.Context(), 500)
	d := h.pageData(r, "审计日志")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = logs
	h.render(w, "admin_audit_logs", d)
}

func (h *Handler) AdminAuditRollback(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()
	al, err := h.st.GetAuditLog(ctx, id)
	if err != nil {
		http.Redirect(w, r, "/admin/audit-logs?flash=审计记录不存在", http.StatusFound)
		return
	}
	// Enforce 3-day rollback window.
	if time.Since(al.CreatedAt) > 3*24*time.Hour {
		http.Redirect(w, r, "/admin/audit-logs?flash=只能回滚 3 天内的操作", http.StatusFound)
		return
	}

	if err := h.rollback(ctx, al); err != nil {
		http.Redirect(w, r, "/admin/audit-logs?flash=回滚失败："+err.Error(), http.StatusFound)
		return
	}

	// Record the rollback itself as an audit entry.
	cur := h.currentUser(r)
	h.logAudit(ctx, cur, "update", al.EntityType, al.EntityID, al.EntityName,
		"", marshalJSON(map[string]string{"rollback_of": al.ID}))

	http.Redirect(w, r, "/admin/audit-logs?flash=回滚成功", http.StatusFound)
}

// rollback dispatches a rollback for a single audit log entry.
func (h *Handler) rollback(ctx context.Context, al *store.AuditLog) error {
	switch al.EntityType {
	case "user":
		return h.rollbackUser(ctx, al)
	case "project":
		return h.rollbackProject(ctx, al)
	case "link":
		return h.rollbackLink(ctx, al)
	case "client":
		return h.rollbackClient(ctx, al)
	case "announcement":
		return h.rollbackAnnouncement(ctx, al)
	case "setting":
		return h.rollbackSetting(ctx, al)
	case "group":
		return h.rollbackGroup(ctx, al)
	case "role":
		return h.rollbackRole(ctx, al)
	case "provider":
		return h.rollbackProvider(ctx, al)
	}
	return fmt.Errorf("不支持回滚：%s/%s", al.EntityType, al.Action)
}

func (h *Handler) rollbackUser(ctx context.Context, al *store.AuditLog) error {
	switch al.Action {
	case "update":
		var u store.User
		if err := json.Unmarshal([]byte(al.BeforeState), &u); err != nil {
			return err
		}
		return h.st.UpdateUser(ctx, u.ID, u.DisplayName, u.Role, u.Active)
	case "delete":
		// Cannot recreate user without password hash — deletion is irreversible.
		return fmt.Errorf("用户删除后无法回滚（密码哈希等数据不可恢复）")
	}
	return nil
}

func (h *Handler) rollbackProject(ctx context.Context, al *store.AuditLog) error {
	switch al.Action {
	case "create":
		var p store.Project
		if err := json.Unmarshal([]byte(al.AfterState), &p); err != nil {
			return err
		}
		return h.st.DeleteProject(ctx, p.ID)
	case "update":
		var p store.Project
		if err := json.Unmarshal([]byte(al.BeforeState), &p); err != nil {
			return err
		}
		return h.st.UpdateProject(ctx, &p)
	case "delete":
		var p store.Project
		if err := json.Unmarshal([]byte(al.BeforeState), &p); err != nil {
			return err
		}
		// Restore DB record; image file may be gone — user must re-upload.
		p.ImageURL = ""
		return h.st.CreateProject(ctx, &p)
	}
	return nil
}

func (h *Handler) rollbackLink(ctx context.Context, al *store.AuditLog) error {
	switch al.Action {
	case "create":
		var l store.FriendLink
		if err := json.Unmarshal([]byte(al.AfterState), &l); err != nil {
			return err
		}
		return h.st.DeleteFriendLink(ctx, l.ID)
	case "update":
		var l store.FriendLink
		if err := json.Unmarshal([]byte(al.BeforeState), &l); err != nil {
			return err
		}
		return h.st.UpdateFriendLink(ctx, l.ID, l.Name, l.URL, l.Icon, l.SortOrder)
	case "delete":
		var l store.FriendLink
		if err := json.Unmarshal([]byte(al.BeforeState), &l); err != nil {
			return err
		}
		return h.st.CreateFriendLink(ctx, l.Name, l.URL, l.Icon, l.SortOrder)
	}
	return nil
}

func (h *Handler) rollbackClient(ctx context.Context, al *store.AuditLog) error {
	switch al.Action {
	case "create":
		var c store.OAuthClient
		if err := json.Unmarshal([]byte(al.AfterState), &c); err != nil {
			return err
		}
		return h.st.DeleteClient(ctx, c.ID)
	case "update":
		var c store.OAuthClient
		if err := json.Unmarshal([]byte(al.BeforeState), &c); err != nil {
			return err
		}
		return h.st.UpdateClient(ctx, c.ID, c.Name, c.Description, c.RedirectURIs, c.Scopes, c.BaseAccess, c.AllowedGroups)
	}
	// delete: cannot restore secret hash — not supported
	return fmt.Errorf("应用删除后无法回滚（密钥不可逆）")
}

func (h *Handler) rollbackAnnouncement(ctx context.Context, al *store.AuditLog) error {
	var state struct {
		ClientID string `json:"client_id"`
		Content  string `json:"content"`
	}
	if err := json.Unmarshal([]byte(al.BeforeState), &state); err != nil {
		return err
	}
	return h.st.SetClientAnnouncement(ctx, state.ClientID, state.Content)
}

func (h *Handler) rollbackSetting(ctx context.Context, al *store.AuditLog) error {
	var m map[string]string
	if err := json.Unmarshal([]byte(al.BeforeState), &m); err != nil {
		return err
	}
	for k, v := range m {
		if err := h.st.SetSetting(ctx, k, v); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) rollbackGroup(ctx context.Context, al *store.AuditLog) error {
	switch al.Action {
	case "create":
		var g store.UserGroup
		if err := json.Unmarshal([]byte(al.AfterState), &g); err != nil {
			return err
		}
		return h.st.DeleteUserGroup(ctx, g.ID)
	case "delete":
		var g store.UserGroup
		if err := json.Unmarshal([]byte(al.BeforeState), &g); err != nil {
			return err
		}
		return h.st.CreateUserGroup(ctx, g.Name, g.Label)
	}
	return nil
}

func (h *Handler) rollbackRole(ctx context.Context, al *store.AuditLog) error {
	switch al.Action {
	case "create":
		var r store.CustomRole
		if err := json.Unmarshal([]byte(al.AfterState), &r); err != nil {
			return err
		}
		return h.st.DeleteCustomRole(ctx, r.Name)
	case "delete":
		var r store.CustomRole
		if err := json.Unmarshal([]byte(al.BeforeState), &r); err != nil {
			return err
		}
		return h.st.CreateCustomRole(ctx, r.Name, r.Label, r.Permissions)
	}
	return nil
}

func (h *Handler) rollbackProvider(ctx context.Context, al *store.AuditLog) error {
	switch al.Action {
	case "create":
		var p store.OIDCProvider
		if err := json.Unmarshal([]byte(al.AfterState), &p); err != nil {
			return err
		}
		return h.st.DeleteOIDCProvider(ctx, p.ID)
	case "update":
		var p store.OIDCProvider
		if err := json.Unmarshal([]byte(al.BeforeState), &p); err != nil {
			return err
		}
		return h.st.UpdateOIDCProvider(ctx, p.ID, p.Name, p.ProviderType, p.Icon,
			p.ClientID, p.ClientSecret, p.IssuerURL, p.AuthorizationURL,
			p.TokenURL, p.UserinfoURL, p.Scopes, p.Enabled, p.AutoRegister)
	case "delete":
		var p store.OIDCProvider
		if err := json.Unmarshal([]byte(al.BeforeState), &p); err != nil {
			return err
		}
		return h.st.CreateOIDCProvider(ctx, p.Name, p.Slug, p.ProviderType, p.Icon,
			p.ClientID, p.ClientSecret, p.IssuerURL, p.AuthorizationURL,
			p.TokenURL, p.UserinfoURL, p.Scopes, p.AutoRegister)
	}
	return nil
}

// ─── Per-App Manager Groups ───────────────────────────────────────────────────

// canManageClient checks whether the given user may manage a specific client.
// Admin always can. If client.ManagerGroups is empty, any user with
// manage_clients permission can. Otherwise the user must be in one of the groups.
func (h *Handler) canManageClient(ctx context.Context, u *store.User, client *store.OAuthClient) bool {
	if u == nil {
		return false
	}
	if u.IsAdmin() {
		return true
	}
	if len(client.ManagerGroups) == 0 {
		return h.userHasPermission(ctx, u, "manage_clients")
	}
	// User must belong to at least one of the manager groups.
	userGroups, err := h.st.GetUserGroups(ctx, u.ID)
	if err != nil {
		return false
	}
	groupSet := make(map[string]bool, len(userGroups))
	for _, g := range userGroups {
		groupSet[strings.ToLower(g.Name)] = true
	}
	for _, mg := range client.ManagerGroups {
		if groupSet[strings.ToLower(mg)] {
			return true
		}
	}
	return false
}

func (h *Handler) AdminClientSetManagers(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()
	client, err := h.st.GetClientByID(ctx, id)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, "应用不存在", id)
		return
	}

	rawGroups := r.Form["manager_groups"]
	var groups []string
	seen := map[string]bool{}
	for _, g := range rawGroups {
		g = strings.ToLower(strings.TrimSpace(g))
		if g != "" && !seen[g] {
			groups = append(groups, g)
			seen[g] = true
		}
	}

	// Validate that named groups exist.
	allGroups, _ := h.st.ListUserGroups(ctx)
	groupSet := map[string]bool{}
	for _, g := range allGroups {
		groupSet[strings.ToLower(g.Name)] = true
	}
	for _, g := range groups {
		if !groupSet[g] {
			http.Redirect(w, r, "/admin/clients/"+id+"?flash=未知分组："+g, http.StatusFound)
			return
		}
	}

	if err := h.st.UpdateClientManagerGroups(ctx, id, groups); err != nil {
		http.Redirect(w, r, "/admin/clients/"+id+"?flash=保存失败："+err.Error(), http.StatusFound)
		return
	}

	cur := h.currentUser(r)
	h.logAudit(ctx, cur, "update", "client", id, client.Name,
		marshalJSON(map[string]any{"manager_groups": client.ManagerGroups}),
		marshalJSON(map[string]any{"manager_groups": groups}))

	http.Redirect(w, r, "/admin/clients/"+id+"?flash=管理权限组已保存", http.StatusFound)
}
