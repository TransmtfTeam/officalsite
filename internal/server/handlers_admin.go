package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"transmtf.com/oidc/internal/store"
)

var providerSlugRe = regexp.MustCompile(`^[a-z0-9-]+$`)

const (
	faviconPNG = "favicon.png"
	faviconJPG = "favicon.jpg"
)

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
	requireChange := r.FormValue("require_password_change") == "1"

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
	u, err := h.st.CreateUser(ctx, email, password, name, role)
	if err != nil {
		d.Flash = "Create failed: " + err.Error()
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}
	if requireChange {
		if err := h.st.SetRequirePasswordChange(ctx, u.ID, true); err != nil {
			// Non-fatal: user was created, just log the flag-set failure.
			_ = err
		}
	}
	http.Redirect(w, r, "/admin/users?flash="+url.QueryEscape("User created: "+email), http.StatusFound)
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
		h.render(w, "admin_users", d)
	} else {
		http.Redirect(w, r, "/admin/users?flash=Updated", http.StatusFound)
	}
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

	http.Redirect(w, r, "/admin/users?flash=Deleted", http.StatusFound)
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
		http.Error(w, "bad request", http.StatusBadRequest)
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
	if requireChange {
		_ = h.st.SetRequirePasswordChange(ctx, id, true)
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
	{"name": "manage_projects", "label": "Manage Projects", "desc": "Create, update, and delete projects"},
	{"name": "manage_clients", "label": "Manage Clients", "desc": "Manage OAuth2/OIDC clients"},
	{"name": "manage_announcements", "label": "Manage Announcements", "desc": "Edit client announcements"},
	{"name": "manage_users", "label": "Manage Users", "desc": "View and manage user accounts"},
	{"name": "manage_groups", "label": "Manage Groups", "desc": "Create and manage user groups"},
	{"name": "manage_providers", "label": "Manage Providers", "desc": "Configure external OIDC providers"},
	{"name": "manage_roles", "label": "Manage Roles", "desc": "Create and edit custom roles"},
	{"name": "manage_settings", "label": "Manage Settings", "desc": "Edit site-wide settings"},
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
	http.Redirect(w, r, "/admin/roles?flash=Role+created", http.StatusFound)
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
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
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

	ticket, tErr := h.issueOneTimeViewTicket(ctx, oneTimeClientCreatedView{
		NewClientID:   clientID,
		NewSecret:     secret,
		Name:          name,
		NewInternalID: internalID,
	})
	if tErr != nil {
		d.Flash = "Created, but failed to prepare result view: " + tErr.Error()
		d.IsError = true
		h.render(w, "admin_client_create", d)
		return
	}
	http.Redirect(w, r, "/admin/clients/created-result?ticket="+url.QueryEscape(ticket), http.StatusFound)
}

func (h *Handler) AdminClientCreatedResult(w http.ResponseWriter, r *http.Request) {
	ticket := strings.TrimSpace(r.URL.Query().Get("ticket"))
	if ticket == "" {
		http.Redirect(w, r, "/admin/clients/new?flash=Result+expired", http.StatusFound)
		return
	}

	var payload oneTimeClientCreatedView
	if err := h.consumeOneTimeViewTicket(r.Context(), ticket, &payload); err != nil {
		http.Redirect(w, r, "/admin/clients/new?flash=Result+expired", http.StatusFound)
		return
	}

	d := h.pageData(r, "App created")
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
	baseAccess := strings.ToLower(strings.TrimSpace(r.FormValue("base_access")))
	allowedGroupsRaw := r.FormValue("allowed_groups")

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
		http.Redirect(w, r, "/admin/clients/"+id+"?flash=Invalid+base+access+policy", http.StatusFound)
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

	ctx := r.Context()
	if name == "" {
		http.Redirect(w, r, "/admin/clients/"+id+"?flash=Name+required", http.StatusFound)
		return
	}
	// Validate custom groups exist to avoid silent misconfiguration.
	groupSet := map[string]bool{}
	groups, err := h.st.ListUserGroups(ctx)
	if err != nil {
		http.Redirect(w, r, "/admin/clients/"+id+"?flash=Group+lookup+failed", http.StatusFound)
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
				http.Redirect(w, r, "/admin/clients/"+id+"?flash=Unknown+group:+"+g, http.StatusFound)
				return
			}
		}
	}
	if err := h.st.UpdateClient(ctx, id, name, desc, uris, scopes, baseAccess, allowedGroups); err != nil {
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

	ticket, tErr := h.issueOneTimeViewTicket(ctx, oneTimeClientSecretView{
		ClientInternalID: id,
		NewSecret:        newSecret,
	})
	if tErr != nil {
		http.Redirect(w, r, "/admin/clients/"+id+"?flash=Reset+succeeded+but+failed+to+prepare+result+view", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/clients/"+id+"/secret?ticket="+url.QueryEscape(ticket), http.StatusFound)
}

func (h *Handler) AdminClientSecretResult(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ticket := strings.TrimSpace(r.URL.Query().Get("ticket"))
	if ticket == "" {
		http.Redirect(w, r, "/admin/clients/"+id+"?flash=Result+expired", http.StatusFound)
		return
	}

	var payload oneTimeClientSecretView
	if err := h.consumeOneTimeViewTicket(r.Context(), ticket, &payload); err != nil {
		http.Redirect(w, r, "/admin/clients/"+id+"?flash=Result+expired", http.StatusFound)
		return
	}
	if payload.ClientInternalID != id {
		http.Redirect(w, r, "/admin/clients/"+id+"?flash=Invalid+result+ticket", http.StatusFound)
		return
	}

	client, err := h.st.GetClientByID(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/clients?flash=Client+not+found", http.StatusFound)
		return
	}

	d := h.pageData(r, "Secret reset")
	d.Flash = "Client Secret has been reset. Save it now (shown only once)."
	d.Data = map[string]any{
		"Client":    client,
		"NewSecret": payload.NewSecret,
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
		clients, _ := h.st.ListClients(ctx)
		d.Data = map[string]any{"Clients": clients}
		h.render(w, "admin_clients", d)
		return
	}
	http.Redirect(w, r, "/admin/clients?flash=Deleted", http.StatusFound)
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
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	file, _, err := r.FormFile("icon_file")
	if err != nil {
		http.Redirect(w, r, "/admin/settings?flash=No+file+selected", http.StatusFound)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		http.Redirect(w, r, "/admin/settings?flash=Failed+to+read+file", http.StatusFound)
		return
	}
	if len(data) == 0 {
		http.Redirect(w, r, "/admin/settings?flash=Empty+file", http.StatusFound)
		return
	}
	mimeType := http.DetectContentType(data)
	fileName, ok := uploadedFaviconFileName(mimeType)
	if !ok {
		http.Redirect(w, r, "/admin/settings?flash=Only+PNG+or+JPG+is+supported", http.StatusFound)
		return
	}
	fullPath := filepath.Join(".", fileName)
	if err := os.WriteFile(fullPath, data, 0o644); err != nil {
		http.Redirect(w, r, "/admin/settings?flash=Failed+to+save+icon", http.StatusFound)
		return
	}
	removeLegacyFavicons(fileName)

	ctx := r.Context()
	_ = h.st.SetSetting(ctx, "site_icon_url", "/"+fileName)

	http.Redirect(w, r, "/admin/settings?flash=Icon+uploaded+as+"+fileName, http.StatusFound)
}

func (h *Handler) AdminSettings(w http.ResponseWriter, r *http.Request) {
	cfg := h.st.GetAllSettings(r.Context())
	d := h.pageData(r, "Site Settings")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
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
	http.Redirect(w, r, "/admin/settings?flash=Settings+saved", http.StatusFound)
}

func (h *Handler) AdminProviders(w http.ResponseWriter, r *http.Request) {
	providers, _ := h.st.ListOIDCProviders(r.Context())
	d := h.pageData(r, "Login Providers")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
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
	autoRegister := r.FormValue("auto_register") == "1"
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
	if err := h.st.CreateOIDCProvider(ctx, name, slug, icon, clientID, clientSecret, issuerURL, strings.Join(scopes, " "), autoRegister); err != nil {
		renderErr("Create failed: " + err.Error())
		return
	}
	http.Redirect(w, r, "/admin/providers?flash=Provider+added", http.StatusFound)
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
	_ = h.st.UpdateOIDCProvider(ctx, p.ID, p.Name, p.Icon, p.ClientID, p.ClientSecret, p.IssuerURL, p.Scopes, !p.Enabled, p.AutoRegister)
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

// User Group Management.

func (h *Handler) AdminGroups(w http.ResponseWriter, r *http.Request) {
	groups, _ := h.st.ListUserGroups(r.Context())
	d := h.pageData(r, "Group Management")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = groups
	h.render(w, "admin_groups", d)
}

func (h *Handler) AdminGroupCreate(w http.ResponseWriter, r *http.Request) {
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
	ctx := r.Context()

	renderErr := func(msg string) {
		groups, _ := h.st.ListUserGroups(ctx)
		d := h.pageData(r, "Group Management")
		d.Flash = msg
		d.IsError = true
		d.Data = groups
		h.render(w, "admin_groups", d)
	}

	if name == "" {
		renderErr("Group name cannot be empty")
		return
	}
	if name == "admin" || name == "member" || name == "user" {
		renderErr("Reserved group names are not allowed (admin/member/user)")
		return
	}
	if err := h.st.CreateUserGroup(ctx, name, label); err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			renderErr("Group name already exists")
		} else {
			renderErr("Create failed: " + err.Error())
		}
		return
	}
	http.Redirect(w, r, "/admin/groups?flash=Group+created", http.StatusFound)
}

func (h *Handler) AdminGroupDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	g, err := h.st.GetUserGroupByID(ctx, id)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, "Group not found", id)
		return
	}
	members, _ := h.st.GetGroupMembers(ctx, id)
	users, _ := h.st.ListUsers(ctx)
	d := h.pageData(r, g.Label+" Group")
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
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	id := r.PathValue("id")
	if err := h.st.DeleteUserGroup(r.Context(), id); err != nil {
		http.Redirect(w, r, "/admin/groups?flash=Delete+failed:+"+err.Error(), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/groups?flash=Group+deleted", http.StatusFound)
}

func (h *Handler) AdminGroupAddMember(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	groupID := r.PathValue("id")
	userID := r.FormValue("user_id")
	if err := h.st.AddUserToGroup(r.Context(), userID, groupID); err != nil {
		http.Redirect(w, r, "/admin/groups/"+groupID+"?flash=Add+failed:+"+err.Error(), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/groups/"+groupID+"?flash=Member+added", http.StatusFound)
}

func (h *Handler) AdminGroupRemoveMember(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	groupID := r.PathValue("id")
	userID := r.PathValue("uid")
	if err := h.st.RemoveUserFromGroup(r.Context(), userID, groupID); err != nil {
		http.Redirect(w, r, "/admin/groups/"+groupID+"?flash=Remove+failed:+"+err.Error(), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/groups/"+groupID+"?flash=Member+removed", http.StatusFound)
}

// AdminUserGroupAdd adds a user to a group from the user-detail page.
func (h *Handler) AdminUserGroupAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	userID := r.PathValue("id")
	groupID := strings.TrimSpace(r.FormValue("group_id"))
	if groupID == "" {
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=Please+select+a+group", http.StatusFound)
		return
	}
	if _, err := h.st.GetUserGroupByID(r.Context(), groupID); err != nil {
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=Group+not+found", http.StatusFound)
		return
	}
	if err := h.st.AddUserToGroup(r.Context(), userID, groupID); err != nil {
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=Add+group+failed:+"+err.Error(), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/users/"+userID+"?flash=Added+to+group", http.StatusFound)
}

// AdminUserGroupRemove removes a user from a group from the user-detail page.
func (h *Handler) AdminUserGroupRemove(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	userID := r.PathValue("id")
	groupID := r.PathValue("gid")
	if err := h.st.RemoveUserFromGroup(r.Context(), userID, groupID); err != nil {
		http.Redirect(w, r, "/admin/users/"+userID+"?flash=Remove+group+failed:+"+err.Error(), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/users/"+userID+"?flash=Removed+from+group", http.StatusFound)
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

// AdminSiteIcon serves the site icon stored in settings (used for PWA manifest / email avatars).
func (h *Handler) AdminSiteIcon(w http.ResponseWriter, r *http.Request) {
	iconURL := h.st.GetSetting(r.Context(), "site_icon_url")
	if iconURL == "" {
		http.NotFound(w, r)
		return
	}
	// Data URL: decode and serve directly.
	const dataPrefix = "data:"
	if strings.HasPrefix(iconURL, dataPrefix) {
		// Format: data:<mime>;base64,<data>
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
	// Regular URL: redirect.
	http.Redirect(w, r, iconURL, http.StatusFound)
}

// AdminVerifyEmail manually marks a user's email as verified.
func (h *Handler) AdminVerifyEmail(w http.ResponseWriter, r *http.Request) {
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
	if err := h.st.SetEmailVerified(ctx, id, true); err != nil {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=Failed+to+verify+email", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/users/"+id+"?flash=Email+verified", http.StatusFound)
}

// AdminUnverifyEmail marks a user's email as unverified.
func (h *Handler) AdminUnverifyEmail(w http.ResponseWriter, r *http.Request) {
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
	if err := h.st.SetEmailVerified(ctx, id, false); err != nil {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=Failed+to+unverify+email", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/users/"+id+"?flash=Re-verification+required", http.StatusFound)
}

// AdminProviderEditPage shows the edit form for an existing OIDC provider.
func (h *Handler) AdminProviderEditPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	p, err := h.st.GetOIDCProviderByID(ctx, id)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, "Provider not found", id)
		return
	}
	d := h.pageData(r, "Edit Login Provider")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = p
	h.render(w, "admin_provider_detail", d)
}

// AdminProviderEdit handles POST to update an existing OIDC provider.
func (h *Handler) AdminProviderEdit(w http.ResponseWriter, r *http.Request) {
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
		h.renderError(w, r, http.StatusNotFound, "Provider not found", id)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	icon := strings.TrimSpace(r.FormValue("icon"))
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := r.FormValue("client_secret")
	issuerURL := strings.TrimSpace(r.FormValue("issuer_url"))
	scopes := normalizeScopes(strings.Fields(strings.TrimSpace(r.FormValue("scopes"))))
	autoRegister := r.FormValue("auto_register") == "1"

	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	renderErr := func(msg string) {
		d := h.pageData(r, "Edit Login Provider")
		d.Data = p
		d.Flash = msg
		d.IsError = true
		h.render(w, "admin_provider_detail", d)
	}

	if name == "" {
		renderErr("Name cannot be empty")
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

	// Keep existing client secret if blank.
	if clientSecret == "" {
		clientSecret = p.ClientSecret
	}
	if clientID == "" {
		clientID = p.ClientID
	}

	if err := h.st.UpdateOIDCProvider(ctx, p.ID, name, icon, clientID, clientSecret, issuerURL, strings.Join(scopes, " "), p.Enabled, autoRegister); err != nil {
		renderErr("Update failed: " + err.Error())
		return
	}
	http.Redirect(w, r, "/admin/providers/"+id+"/edit?flash=Updated", http.StatusFound)
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
	raw, err := h.st.GetWebAuthnSession(ctx, ticket)
	if err != nil {
		return err
	}
	defer h.st.DeleteWebAuthnSession(ctx, ticket)
	return json.Unmarshal([]byte(raw), out)
}

