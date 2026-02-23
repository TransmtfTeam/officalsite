package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"transmtf.com/oidc/internal/store"
)

var providerSlugRe = regexp.MustCompile(`^[a-z0-9-]+$`)

func (h *Handler) AdminDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := h.pageData(r, "Admin Dashboard")
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
	d := h.pageData(r, "User Management")
	d.Data = map[string]any{
		"Users":       users,
		"CustomRoles": customRoles,
	}
	h.render(w, "admin_users", d)
}

func (h *Handler) AdminUserCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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

	ctx := r.Context()
	d := h.pageData(r, "User Management")
	users, _ := h.st.ListUsers(ctx)
	customRoles, _ := h.st.ListCustomRoles(ctx)
	d.Data = map[string]any{"Users": users, "CustomRoles": customRoles}
	if role == "admin" && !h.isSystemAdminUser(h.currentUser(r)) {
		d.Flash = "Only system admin can assign admin role"
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}
	_, err := h.st.CreateUser(ctx, email, password, name, role)
	if err != nil {
		d.Flash = "Create failed: " + err.Error()
		d.IsError = true
	} else {
		d.Flash = "User created: " + email
	}
	h.render(w, "admin_users", d)
}

func (h *Handler) AdminUserUpdate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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
	d := h.pageData(r, "User Management")
	users, _ := h.st.ListUsers(ctx)
	customRoles, _ := h.st.ListCustomRoles(ctx)
	d.Data = map[string]any{"Users": users, "CustomRoles": customRoles}

	cur := h.currentUser(r)
	// Protect system admin
	targetUser, err := h.st.GetUserByID(ctx, id)
	if err != nil {
		d.Flash = "User not found"
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}
	if targetUser.IsAdmin() && !h.isSystemAdminUser(cur) {
		d.Flash = "Cannot modify admin account"
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}
	if role == "admin" && !h.isSystemAdminUser(cur) {
		d.Flash = "Only system admin can assign admin role"
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}
	if h.isSystemAdminUser(targetUser) {
		role = "admin"
		active = true
	}

	if err := h.st.UpdateUser(ctx, id, name, role, active); err != nil {
		d.Flash = "Update failed: " + err.Error()
		d.IsError = true
	} else {
		d.Flash = "Updated"
	}
	h.render(w, "admin_users", d)
}

func (h *Handler) AdminUserDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	id := r.PathValue("id")
	cur := h.currentUser(r)
	ctx := r.Context()
	d := h.pageData(r, "User Management")

	targetUser, err := h.st.GetUserByID(ctx, id)
	if err != nil {
		users, _ := h.st.ListUsers(ctx)
		customRoles, _ := h.st.ListCustomRoles(ctx)
		d.Data = map[string]any{"Users": users, "CustomRoles": customRoles}
		d.Flash = "User not found"
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}
	if targetUser.IsAdmin() && !h.isSystemAdminUser(cur) {
		users, _ := h.st.ListUsers(ctx)
		customRoles, _ := h.st.ListCustomRoles(ctx)
		d.Data = map[string]any{"Users": users, "CustomRoles": customRoles}
		d.Flash = "Cannot modify admin account"
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}

	if cur != nil && cur.ID == id {
		users, _ := h.st.ListUsers(ctx)
		customRoles, _ := h.st.ListCustomRoles(ctx)
		d.Data = map[string]any{"Users": users, "CustomRoles": customRoles}
		d.Flash = "Cannot delete yourself"
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}

	if err := h.st.DeleteUser(ctx, id); err != nil {
		users, _ := h.st.ListUsers(ctx)
		customRoles, _ := h.st.ListCustomRoles(ctx)
		d.Data = map[string]any{"Users": users, "CustomRoles": customRoles}
		d.Flash = "Delete failed: " + err.Error()
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}

	users, _ := h.st.ListUsers(ctx)
	customRoles, _ := h.st.ListCustomRoles(ctx)
	d.Data = map[string]any{"Users": users, "CustomRoles": customRoles}
	d.Flash = "Deleted"
	h.render(w, "admin_users", d)
}


func (h *Handler) AdminUserDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	u, err := h.st.GetUserByID(ctx, id)
	if err != nil {
        h.renderError(w, r, http.StatusNotFound, "User not found", id)
		return
	}
	identities, _ := h.st.GetUserIdentitiesByUserID(ctx, id)
	sessions, _ := h.st.GetSessionsByUserID(ctx, id)
	accessTokens, _ := h.st.GetAccessTokensByUserID(ctx, id)
	refreshTokens, _ := h.st.GetRefreshTokensByUserID(ctx, id)
	passkeys, _ := h.st.GetPasskeyCredentialsByUserID(ctx, id)

	d := h.pageData(r, "User Details")
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
		"IsSystemAdmin":     h.isSystemAdminUser(u),
		"CurrentIsSysAdmin": h.isSystemAdminUser(h.currentUser(r)),
	}
	h.render(w, "admin_user_detail", d)
}

func (h *Handler) AdminUserResetPassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	id := r.PathValue("id")
	newPass := r.FormValue("new_password")
	ctx := r.Context()

	targetUser, err := h.st.GetUserByID(ctx, id)
	if err != nil {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=User+not+found", http.StatusFound)
		return
	}
	// Only system admin may modify another admin's password.
	cur := h.currentUser(r)
	if targetUser.IsAdmin() && !h.isSystemAdminUser(cur) {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=Cannot+modify+admin+account", http.StatusFound)
		return
	}

	if len(newPass) < 8 {
        http.Redirect(w, r, "/admin/users/"+id+"?flash=Password+must+be+at+least+8+chars", http.StatusFound)
		return
	}
	if err := h.st.UpdatePassword(ctx, id, newPass); err != nil {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=Password+reset+failed", http.StatusFound)
		return
	}
	go h.sendPasswordResetEmail(context.Background(), targetUser.Email, targetUser.DisplayName, newPass)
    http.Redirect(w, r, "/admin/users/"+id+"?flash=Password+reset", http.StatusFound)
}

func (h *Handler) AdminUserDisable2FA(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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
		http.Redirect(w, r, "/admin/users/"+id+"?flash=User+not+found", http.StatusFound)
		return
	}
	cur := h.currentUser(r)
	if targetUser.IsAdmin() && !h.isSystemAdminUser(cur) {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=Cannot+modify+admin+account", http.StatusFound)
		return
	}

	if err := h.st.DisableTOTP(ctx, id); err != nil {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=Disable+2FA+failed", http.StatusFound)
		return
	}
    http.Redirect(w, r, "/admin/users/"+id+"?flash=2FA+disabled", http.StatusFound)
}

func (h *Handler) AdminUserRevokeSession(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=User+not+found", http.StatusFound)
		return
	}
	if targetUser.IsAdmin() && !h.isSystemAdminUser(h.currentUser(r)) {
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=Cannot+modify+admin+account", http.StatusFound)
		return
	}
	_ = h.st.DeleteSession(r.Context(), sessID)
	http.Redirect(w, r, "/admin/users/"+userID+"?flash=Session+revoked", http.StatusFound)
}

func (h *Handler) AdminUserRevokeToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=User+not+found", http.StatusFound)
		return
	}
	if targetUser.IsAdmin() && !h.isSystemAdminUser(h.currentUser(r)) {
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=Cannot+modify+admin+account", http.StatusFound)
		return
	}
	if tokenType == "refresh" {
		_ = h.st.RevokeRefreshTokenByID(ctx, tokenID)
	} else {
		_ = h.st.RevokeAccessTokenByID(ctx, tokenID)
	}
	http.Redirect(w, r, "/admin/users/"+userID+"?flash=Token+revoked", http.StatusFound)
}


// allPermissions defines every available permission for custom roles.
var allPermissions = []map[string]string{
	{"name": "manage_projects", "label": "管理项目", "desc": "首页项目增删改"},
	{"name": "manage_clients", "label": "管理应用", "desc": "OAuth2/OIDC 应用管理"},
	{"name": "manage_announcements", "label": "管理公告", "desc": "各应用公告内容"},
	{"name": "manage_users", "label": "管理用户", "desc": "查看及修改用户账户"},
	{"name": "manage_providers", "label": "管理登录方式", "desc": "外部 OIDC 提供商"},
	{"name": "manage_roles", "label": "管理角色", "desc": "自定义角色增删改"},
	{"name": "manage_settings", "label": "管理设置", "desc": "站点全局设置"},
}

func (h *Handler) AdminRoles(w http.ResponseWriter, r *http.Request) {
	roles, _ := h.st.ListCustomRoles(r.Context())
	d := h.pageData(r, "Role Management")
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
		http.Error(w, "bad request", http.StatusBadRequest)
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
	d := h.pageData(r, "Role Management")
	roles, _ := h.st.ListCustomRoles(ctx)
	d.Data = map[string]any{
		"Roles":       roles,
		"Permissions": allPermissions,
	}
	if name == "" {
		d.Flash = "Role name cannot be empty"
		d.IsError = true
		h.render(w, "admin_roles", d)
		return
	}
	if err := h.st.CreateCustomRole(ctx, name, label, permissions); err != nil {
		d.Flash = "Create failed: " + err.Error()
		d.IsError = true
		h.render(w, "admin_roles", d)
		return
	}
	roles, _ = h.st.ListCustomRoles(ctx)
	d.Data = map[string]any{
		"Roles":       roles,
		"Permissions": allPermissions,
	}
	d.Flash = "Role created"
	h.render(w, "admin_roles", d)
}

func (h *Handler) AdminRoleDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	name := r.PathValue("name")
	if err := h.st.DeleteCustomRole(r.Context(), name); err != nil {
		http.Redirect(w, r, "/admin/roles?flash=Delete+failed:+"+err.Error(), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/roles", http.StatusFound)
}


func (h *Handler) AdminClients(w http.ResponseWriter, r *http.Request) {
	clients, _ := h.st.ListClients(r.Context())
	d := h.pageData(r, "App Management")
	d.Data = map[string]any{"Clients": clients}
	h.render(w, "admin_clients", d)
}

func (h *Handler) AdminClientCreatePage(w http.ResponseWriter, r *http.Request) {
	d := h.pageData(r, "Create App")
	h.render(w, "admin_client_create", d)
}

func (h *Handler) AdminClientCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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
	d := h.pageData(r, "Create App")

	if name == "" {
		d.Flash = "App name cannot be empty"
		d.IsError = true
		h.render(w, "admin_client_create", d)
		return
	}
	if len(uris) == 0 {
		d.Flash = "At least one Redirect URI is required"
		d.IsError = true
		h.render(w, "admin_client_create", d)
		return
	}
	for _, u := range uris {
		if !isAllowedAbsoluteURL(u) {
			d.Flash = "Redirect URI is invalid: " + u
			d.IsError = true
			h.render(w, "admin_client_create", d)
			return
		}
	}

	clientID, secret, err := h.st.CreateClient(ctx, name, desc, uris, scopes)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
            d.Flash = "Client name already exists, use another name"
		} else {
			d.Flash = "Create failed: " + err.Error()
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
	}

	d.Flash = "Created"
	d.Data = map[string]any{
		"NewClientID":  clientID,
		"NewSecret":    secret,
		"Name":         name,
		"NewInternalID": internalID,
	}
	h.render(w, "admin_client_created", d)
}

func (h *Handler) AdminClientDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	client, err := h.st.GetClientByID(ctx, id)
	if err != nil {
        h.renderError(w, r, http.StatusNotFound, "Client not found", id)
		return
	}
	ann := h.st.GetClientAnnouncement(ctx, client.ClientID)
	d := h.pageData(r, client.Name)
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = map[string]any{
		"Client":       client,
		"Announcement": ann,
	}
	h.render(w, "admin_client_detail", d)
}

func (h *Handler) AdminClientUpdate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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
	if name == "" {
		http.Redirect(w, r, "/admin/clients/"+id+"?flash=Name+required", http.StatusFound)
		return
	}
	if err := h.st.UpdateClient(ctx, id, name, desc, uris, scopes); err != nil {
		msg := "Update failed"
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
            msg = "Client name already exists"
		}
		http.Redirect(w, r, "/admin/clients/"+id+"?flash="+msg, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/clients/"+id+"?flash=Updated", http.StatusFound)
}

func (h *Handler) AdminClientResetSecret(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	id := r.PathValue("id")
	ctx := r.Context()
	newSecret, err := h.st.ResetClientSecret(ctx, id)
	if err != nil {
		http.Redirect(w, r, "/admin/clients/"+id+"?flash=Reset+failed", http.StatusFound)
		return
	}
	client, _ := h.st.GetClientByID(ctx, id)
    d := h.pageData(r, "Secret reset")
	d.Flash = "Client Secret has been reset. Save it now (shown only once)."
	d.Data = map[string]any{
		"Client":    client,
		"NewSecret": newSecret,
	}
	h.render(w, "admin_client_secret", d)
}

func (h *Handler) AdminClientDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	id := r.PathValue("id")
	ctx := r.Context()
	d := h.pageData(r, "App Management")
	if err := h.st.DeleteClient(ctx, id); err != nil {
		d.Flash = "Delete failed: " + err.Error()
		d.IsError = true
	} else {
		d.Flash = "Deleted"
	}
	clients, _ := h.st.ListClients(ctx)
	d.Data = map[string]any{"Clients": clients}
	h.render(w, "admin_clients", d)
}


func (h *Handler) AdminAnnouncements(w http.ResponseWriter, r *http.Request) {
	clients, _ := h.st.ListClients(r.Context())
	type clientWithAnn struct {
		*store.OAuthClient
		Announcement string
	}
	var items []clientWithAnn
	for _, c := range clients {
		items = append(items, clientWithAnn{
			OAuthClient:  c,
			Announcement: h.st.GetClientAnnouncement(r.Context(), c.ClientID),
		})
	}
	d := h.pageData(r, "App Announcements")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = items
	h.render(w, "admin_announcements", d)
}

func (h *Handler) AdminAnnouncementSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	clientID := r.PathValue("clientid")
	content := r.FormValue("content")
	ctx := r.Context()
	_, err := h.st.GetClientByClientID(ctx, clientID)
	if err != nil {
        http.Redirect(w, r, "/admin/announcements?flash=Client+not+found", http.StatusFound)
		return
	}
	if err := h.st.SetClientAnnouncement(ctx, clientID, content); err != nil {
		http.Redirect(w, r, "/admin/announcements?flash=Save+failed", http.StatusFound)
		return
	}
    http.Redirect(w, r, "/admin/announcements?flash=Announcement+saved", http.StatusFound)
}

func (h *Handler) AdminSettingsUploadIcon(w http.ResponseWriter, r *http.Request) {
	// Limit upload size to 512 KB.
	r.Body = http.MaxBytesReader(w, r.Body, 512*1024)
	if err := r.ParseMultipartForm(512 * 1024); err != nil {
		http.Redirect(w, r, "/admin/settings?flash=File+too+large+(max+512KB)", http.StatusFound)
		return
	}
	if !h.verifyCSRFValue(h.csrfTokenFromRequest(r), r.FormValue("csrf_token")) {
		h.csrfFailed(w, r)
		return
	}
	file, header, err := r.FormFile("icon_file")
	if err != nil {
		http.Redirect(w, r, "/admin/settings?flash=No+file+selected", http.StatusFound)
		return
	}
	defer file.Close()

	// Determine MIME type from Content-Type or fall back to octet-stream.
	mimeType := header.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "image/png"
	}
	// Only allow image types.
	allowed := map[string]bool{
		"image/png": true, "image/jpeg": true, "image/gif": true,
		"image/x-icon": true, "image/vnd.microsoft.icon": true,
		"image/svg+xml": true, "image/webp": true,
	}
	if !allowed[mimeType] {
		http.Redirect(w, r, "/admin/settings?flash=Unsupported+file+type", http.StatusFound)
		return
	}

	data, err := io.ReadAll(file)
	if err != nil {
		http.Redirect(w, r, "/admin/settings?flash=Failed+to+read+file", http.StatusFound)
		return
	}

	dataURL := fmt.Sprintf("data:%s;base64,%s", mimeType, base64.StdEncoding.EncodeToString(data))
	ctx := r.Context()
	_ = h.st.SetSetting(ctx, "site_icon_url", dataURL)

	http.Redirect(w, r, "/admin/settings?flash=Icon+updated", http.StatusFound)
}

func (h *Handler) AdminSettings(w http.ResponseWriter, r *http.Request) {
	cfg := h.st.GetAllSettings(r.Context())
	d := h.pageData(r, "Site Settings")
	d.Data = cfg
	h.render(w, "admin_settings", d)
}

func (h *Handler) AdminSettingsSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	ctx := r.Context()
	keys := []string{
		"site_name", "contact_email", "site_icon_url",
		"ann_zh", "ann_en",
		"tos_content", "privacy_content",
		"email_provider",
		"smtp_host", "smtp_port", "smtp_user", "smtp_from",
		"resend_from",
		"email_tpl_welcome", "email_tpl_password_reset",
	}
	for _, k := range keys {
		_ = h.st.SetSetting(ctx, k, r.FormValue(k))
	}
	// Password/key fields: only overwrite when a new value is provided.
	for _, k := range []string{"smtp_pass", "resend_api_key"} {
		if v := r.FormValue(k); v != "" {
			_ = h.st.SetSetting(ctx, k, v)
		}
	}
	cfg := h.st.GetAllSettings(ctx)
	d := h.pageData(r, "Site Settings")
	d.Data = cfg
	d.Flash = "Settings saved"
	h.render(w, "admin_settings", d)
}

func (h *Handler) AdminProviders(w http.ResponseWriter, r *http.Request) {
	providers, _ := h.st.ListOIDCProviders(r.Context())
	d := h.pageData(r, "Login Providers")
	d.Data = providers
	h.render(w, "admin_providers", d)
}

func (h *Handler) AdminProviderCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	slug := strings.TrimSpace(r.FormValue("slug"))
	icon := strings.TrimSpace(r.FormValue("icon"))
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := r.FormValue("client_secret")
	issuerURL := strings.TrimSpace(r.FormValue("issuer_url"))
	scopes := normalizeScopes(strings.Fields(strings.TrimSpace(r.FormValue("scopes"))))
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	renderErr := func(msg string) {
		d := h.pageData(r, "Login Providers")
		providers, _ := h.st.ListOIDCProviders(r.Context())
		d.Data = providers
		d.Flash = msg
		d.IsError = true
		h.render(w, "admin_providers", d)
	}

	if name == "" || slug == "" || clientID == "" || clientSecret == "" || issuerURL == "" {
        renderErr("Please fill all provider fields")
		return
	}
	if !providerSlugRe.MatchString(slug) {
		renderErr("Slug may contain only lowercase letters, numbers, and hyphens")
		return
	}
	if !isAllowedAbsoluteURL(issuerURL) {
		renderErr("Issuer URL must be HTTPS, or HTTP for localhost/127.0.0.1")
		return
	}
	if !containsScope(scopes, "openid") {
		renderErr("Scopes must include openid")
		return
	}

	ctx := r.Context()
	err := h.st.CreateOIDCProvider(ctx, name, slug, icon, clientID, clientSecret, issuerURL, strings.Join(scopes, " "))
	d := h.pageData(r, "Login Providers")
	providers, _ := h.st.ListOIDCProviders(ctx)
	d.Data = providers
	if err != nil {
		d.Flash = "Create failed: " + err.Error()
		d.IsError = true
	} else {
		d.Flash = "Provider added"
	}
	h.render(w, "admin_providers", d)
}

func (h *Handler) AdminProviderToggle(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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
        h.renderError(w, r, http.StatusNotFound, "Not found", id)
		return
	}
	_ = h.st.UpdateOIDCProvider(ctx, p.ID, p.Name, p.Icon, p.ClientID, p.ClientSecret, p.IssuerURL, p.Scopes, !p.Enabled)
	http.Redirect(w, r, "/admin/providers", http.StatusFound)
}

func (h *Handler) AdminProviderDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	id := r.PathValue("id")
	_ = h.st.DeleteOIDCProvider(r.Context(), id)
	http.Redirect(w, r, "/admin/providers", http.StatusFound)
}
