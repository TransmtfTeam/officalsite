package server

import (
	"context"
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
	_, err := h.st.CreateUser(ctx, email, password, name, role)
	d := h.pageData(r, "User Management")
	users, _ := h.st.ListUsers(ctx)
	customRoles, _ := h.st.ListCustomRoles(ctx)
	d.Data = map[string]any{"Users": users, "CustomRoles": customRoles}
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
	// Protect system admin
	targetUser, _ := h.st.GetUserByID(ctx, id)
	if targetUser != nil && targetUser.Email == h.cfg.AdminEmail {
		role = "admin"
		active = true
	}

	err := h.st.UpdateUser(ctx, id, name, role, active)
	d := h.pageData(r, "User Management")
	users, _ := h.st.ListUsers(ctx)
	customRoles, _ := h.st.ListCustomRoles(ctx)
	d.Data = map[string]any{"Users": users, "CustomRoles": customRoles}
	if err != nil {
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

	targetUser, _ := h.st.GetUserByID(ctx, id)
	if targetUser != nil && targetUser.Email == h.cfg.AdminEmail {
		users, _ := h.st.ListUsers(ctx)
		customRoles, _ := h.st.ListCustomRoles(ctx)
		d.Data = map[string]any{"Users": users, "CustomRoles": customRoles}
		d.Flash = "System admin cannot be deleted"
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
		"User":          u,
		"Identities":    identities,
		"Sessions":      sessions,
		"AccessTokens":  accessTokens,
		"RefreshTokens": refreshTokens,
		"Passkeys":      passkeys,
		"IsSystemAdmin": u.Email == h.cfg.AdminEmail,
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
	if len(newPass) < 8 {
        http.Redirect(w, r, "/admin/users/"+id+"?flash=Password+must+be+at+least+8+chars", http.StatusFound)
		return
	}
	if err := h.st.UpdatePassword(ctx, id, newPass); err != nil {
		http.Redirect(w, r, "/admin/users/"+id+"?flash=Password+reset+failed", http.StatusFound)
		return
	}
	if u, err := h.st.GetUserByID(ctx, id); err == nil {
		go h.sendPasswordResetEmail(context.Background(), u.Email, u.DisplayName, newPass)
	}
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
	if tokenType == "refresh" {
		_ = h.st.RevokeRefreshTokenByID(ctx, tokenID)
	} else {
		_ = h.st.RevokeAccessTokenByID(ctx, tokenID)
	}
	http.Redirect(w, r, "/admin/users/"+userID+"?flash=Token+revoked", http.StatusFound)
}


func (h *Handler) AdminRoles(w http.ResponseWriter, r *http.Request) {
	roles, _ := h.st.ListCustomRoles(r.Context())
	d := h.pageData(r, "Role Management")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = roles
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
	ctx := r.Context()
	d := h.pageData(r, "Role Management")
	roles, _ := h.st.ListCustomRoles(ctx)
	d.Data = roles
	if name == "" {
		d.Flash = "Role name cannot be empty"
		d.IsError = true
		h.render(w, "admin_roles", d)
		return
	}
	if err := h.st.CreateCustomRole(ctx, name, label); err != nil {
		d.Flash = "Create failed: " + err.Error()
		d.IsError = true
		h.render(w, "admin_roles", d)
		return
	}
	roles, _ = h.st.ListCustomRoles(ctx)
	d.Data = roles
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
		"smtp_host", "smtp_port", "smtp_user", "smtp_pass", "smtp_from",
		"resend_api_key", "resend_from",
	}
	for _, k := range keys {
		_ = h.st.SetSetting(ctx, k, r.FormValue(k))
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
