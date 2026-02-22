package server

import (
	"net/http"
	"regexp"
	"strings"
)

var providerSlugRe = regexp.MustCompile(`^[a-z0-9-]+$`)

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
	d := h.pageData(r, "用户管理")
	d.Data = users
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
	if role != "user" && role != "member" && role != "admin" {
		role = "user"
	}

	ctx := r.Context()
	_, err := h.st.CreateUser(ctx, email, password, name, role)
	d := h.pageData(r, "用户管理")
	if err != nil {
		users, _ := h.st.ListUsers(ctx)
		d.Data = users
		d.Flash = "创建失败: " + err.Error()
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}

	d.Flash = "用户已创建: " + email
	users, _ := h.st.ListUsers(ctx)
	d.Data = users
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
	if role != "user" && role != "member" && role != "admin" {
		role = "user"
	}

	ctx := r.Context()
	err := h.st.UpdateUser(ctx, id, name, role, active)
	d := h.pageData(r, "用户管理")
	users, _ := h.st.ListUsers(ctx)
	d.Data = users
	if err != nil {
		d.Flash = "更新失败: " + err.Error()
		d.IsError = true
	} else {
		d.Flash = "更新成功"
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
	d := h.pageData(r, "用户管理")

	if cur != nil && cur.ID == id {
		users, _ := h.st.ListUsers(ctx)
		d.Data = users
		d.Flash = "不能删除自己"
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}

	if err := h.st.DeleteUser(ctx, id); err != nil {
		users, _ := h.st.ListUsers(ctx)
		d.Data = users
		d.Flash = "删除失败: " + err.Error()
		d.IsError = true
		h.render(w, "admin_users", d)
		return
	}

	users, _ := h.st.ListUsers(ctx)
	d.Data = users
	d.Flash = "删除成功"
	h.render(w, "admin_users", d)
}

func (h *Handler) AdminClients(w http.ResponseWriter, r *http.Request) {
	clients, _ := h.st.ListClients(r.Context())
	d := h.pageData(r, "应用管理")
	d.Data = map[string]any{"Clients": clients}
	h.render(w, "admin_clients", d)
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
	clients, _ := h.st.ListClients(ctx)
	d := h.pageData(r, "应用管理")

	if name == "" {
		d.Data = map[string]any{"Clients": clients}
		d.Flash = "应用名称不能为空"
		d.IsError = true
		h.render(w, "admin_clients", d)
		return
	}
	if len(uris) == 0 {
		d.Data = map[string]any{"Clients": clients}
		d.Flash = "至少需要一个 Redirect URI"
		d.IsError = true
		h.render(w, "admin_clients", d)
		return
	}
	for _, u := range uris {
		if !isAllowedAbsoluteURL(u) {
			d.Data = map[string]any{"Clients": clients}
			d.Flash = "Redirect URI 不合法: " + u
			d.IsError = true
			h.render(w, "admin_clients", d)
			return
		}
	}

	clientID, secret, err := h.st.CreateClient(ctx, name, desc, uris, scopes)
	if err != nil {
		d.Data = map[string]any{"Clients": clients}
		d.Flash = "创建失败: " + err.Error()
		d.IsError = true
		h.render(w, "admin_clients", d)
		return
	}

	clients, _ = h.st.ListClients(ctx)
	d.Flash = "创建成功"
	d.Data = map[string]any{
		"Clients":     clients,
		"NewClientID": clientID,
		"NewSecret":   secret,
	}
	h.render(w, "admin_clients", d)
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
	d := h.pageData(r, "应用管理")
	if err := h.st.DeleteClient(ctx, id); err != nil {
		d.Flash = "删除失败: " + err.Error()
		d.IsError = true
	} else {
		d.Flash = "删除成功"
	}
	clients, _ := h.st.ListClients(ctx)
	d.Data = map[string]any{"Clients": clients}
	h.render(w, "admin_clients", d)
}

func (h *Handler) AdminSettings(w http.ResponseWriter, r *http.Request) {
	cfg := h.st.GetAllSettings(r.Context())
	d := h.pageData(r, "站点设置")
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
	keys := []string{"site_name", "contact_email", "ann_zh", "ann_en", "tos_content", "privacy_content"}
	for _, k := range keys {
		_ = h.st.SetSetting(ctx, k, r.FormValue(k))
	}
	cfg := h.st.GetAllSettings(ctx)
	d := h.pageData(r, "站点设置")
	d.Data = cfg
	d.Flash = "设置已保存"
	h.render(w, "admin_settings", d)
}

func (h *Handler) AdminProviders(w http.ResponseWriter, r *http.Request) {
	providers, _ := h.st.ListOIDCProviders(r.Context())
	d := h.pageData(r, "登录方式")
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

	renderProviderError := func(msg string) {
		d := h.pageData(r, "登录方式")
		providers, _ := h.st.ListOIDCProviders(r.Context())
		d.Data = providers
		d.Flash = msg
		d.IsError = true
		h.render(w, "admin_providers", d)
	}

	if name == "" || slug == "" || clientID == "" || clientSecret == "" || issuerURL == "" {
		renderProviderError("请填写完整的提供商配置")
		return
	}
	if !providerSlugRe.MatchString(slug) {
		renderProviderError("Slug 只能包含小写字母、数字、-")
		return
	}
	if !isAllowedAbsoluteURL(issuerURL) {
		renderProviderError("Issuer URL 必须是 HTTPS，或 localhost/127.0.0.1 的 HTTP")
		return
	}
	if !containsScope(scopes, "openid") {
		renderProviderError("Scopes 必须包含 openid")
		return
	}

	ctx := r.Context()
	err := h.st.CreateOIDCProvider(ctx, name, slug, icon, clientID, clientSecret, issuerURL, strings.Join(scopes, " "))
	d := h.pageData(r, "登录方式")
	providers, _ := h.st.ListOIDCProviders(ctx)
	d.Data = providers
	if err != nil {
		d.Flash = "创建失败: " + err.Error()
		d.IsError = true
	} else {
		d.Flash = "登录方式已添加"
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
		h.renderError(w, r, http.StatusNotFound, "不存在", id)
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
