package server

import (
	"net/http"
	"strings"
	"time"

	"transmtf.com/oidc/internal/store"
)

// registerAdminClientsAPIRoutes wires the JSON admin OAuth-client API under
// /api/v1. It mirrors the server-rendered admin client handlers
// (handlers_admin.go: AdminClients/AdminClientCreate/AdminClientDetail/
// AdminClientUpdate/AdminClientResetSecret/AdminClientDelete/
// AdminClientSetManagers) but speaks JSON. Auth guards match the HTML routes
// (server.go:531-540): list/create/detail/update/reset-secret require the
// "manage_clients" permission, while DELETE and manager-group changes require
// apiRequireAdmin.
//
// JSON-body and DELETE mutations are wrapped with requireAPICSRF. GET reads are
// not. Validation, store calls and audit logging are copied verbatim from the
// HTML handlers; only input parsing (form→JSON) and output (redirect/render
// →apiOK/apiErr) change.
//
// One-time secret: the HTML AdminClientCreate stashed the plaintext secret in a
// one-time view ticket and redirected. The JSON API instead returns the
// plaintext directly in the create/reset responses; only the hash is persisted
// (the store already hashes + stores and returns the plaintext in-memory).
func registerAdminClientsAPIRoutes(mux *http.ServeMux, h *Handler) {
	// ── 应用管理 (manage_clients) ─────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/admin/clients",
		h.apiRequirePermission("manage_clients")(h.APIAdminClients))
	mux.HandleFunc("POST /api/v1/admin/clients",
		h.apiRequirePermission("manage_clients")(h.requireAPICSRF(h.APIAdminClientCreate)))
	mux.HandleFunc("GET /api/v1/admin/clients/{id}",
		h.apiRequirePermission("manage_clients")(h.APIAdminClientDetail))
	mux.HandleFunc("PATCH /api/v1/admin/clients/{id}",
		h.apiRequirePermission("manage_clients")(h.requireAPICSRF(h.APIAdminClientUpdate)))
	mux.HandleFunc("POST /api/v1/admin/clients/{id}/reset-secret",
		h.apiRequirePermission("manage_clients")(h.requireAPICSRF(h.APIAdminClientResetSecret)))

	// ── 应用删除 / 管理权限组 (apiRequireAdmin) ────────────────────────────────────
	mux.HandleFunc("DELETE /api/v1/admin/clients/{id}",
		h.apiRequireAdmin(h.requireAPICSRF(h.APIAdminClientDelete)))
	mux.HandleFunc("POST /api/v1/admin/clients/{id}/managers",
		h.apiRequireAdmin(h.requireAPICSRF(h.APIAdminClientSetManagers)))
}

// ── DTOs ─────────────────────────────────────────────────────────────────────

// adminClientDTO exposes an OAuth client's safe fields. It never exposes
// SecretHash.
type adminClientDTO struct {
	ID            string   `json:"id"`
	ClientID      string   `json:"clientId"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	RedirectURIs  []string `json:"redirectUris"`
	Scopes        []string `json:"scopes"`
	BaseAccess    string   `json:"baseAccess"`
	AllowedGroups []string `json:"allowedGroups"`
	ManagerGroups []string `json:"managerGroups"`
	CreatedAt     string   `json:"createdAt"`
}

func toAdminClientDTO(c *store.OAuthClient) *adminClientDTO {
	if c == nil {
		return nil
	}
	return &adminClientDTO{
		ID:            c.ID,
		ClientID:      c.ClientID,
		Name:          c.Name,
		Description:   c.Description,
		RedirectURIs:  c.RedirectURIs,
		Scopes:        c.Scopes,
		BaseAccess:    c.BaseAccess,
		AllowedGroups: c.AllowedGroups,
		ManagerGroups: c.ManagerGroups,
		CreatedAt:     c.CreatedAt.Format(time.RFC3339),
	}
}

func toAdminClientDTOs(cs []*store.OAuthClient) []*adminClientDTO {
	out := make([]*adminClientDTO, 0, len(cs))
	for _, c := range cs {
		out = append(out, toAdminClientDTO(c))
	}
	return out
}

// adminClientIntegrationDTO mirrors the issuer-based integration endpoints the
// admin_client_detail template renders.
type adminClientIntegrationDTO struct {
	Issuer                string `json:"issuer"`
	DiscoveryEndpoint     string `json:"discoveryEndpoint"`
	AuthorizationEndpoint string `json:"authorizationEndpoint"`
	TokenEndpoint         string `json:"tokenEndpoint"`
	UserinfoEndpoint      string `json:"userinfoEndpoint"`
	JWKSEndpoint          string `json:"jwksEndpoint"`
}

func (h *Handler) adminClientIntegration() *adminClientIntegrationDTO {
	issuer := strings.TrimRight(h.cfg.Issuer, "/")
	return &adminClientIntegrationDTO{
		Issuer:                issuer,
		DiscoveryEndpoint:     issuer + "/.well-known/openid-configuration",
		AuthorizationEndpoint: issuer + "/oauth2/authorize",
		TokenEndpoint:         issuer + "/oauth2/token",
		UserinfoEndpoint:      issuer + "/oauth2/userinfo",
		JWKSEndpoint:          issuer + "/.well-known/jwks.json",
	}
}

// ── Input bodies ───────────────────────────────────────────────────────────────

// adminClientCreateInput mirrors the form fields read by AdminClientCreate.
// RedirectURIs is the newline-separated redirect_uris textarea; Scopes is the
// space-separated scopes field.
type adminClientCreateInput struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	RedirectURIs string `json:"redirectUris"`
	Scopes       string `json:"scopes"`
}

// adminClientUpdateInput mirrors the form fields read by AdminClientUpdate.
type adminClientUpdateInput struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	RedirectURIs  string `json:"redirectUris"`
	Scopes        string `json:"scopes"`
	BaseAccess    string `json:"baseAccess"`
	AllowedGroups string `json:"allowedGroups"`
}

// adminClientSetManagersInput mirrors the manager_groups field of
// AdminClientSetManagers.
type adminClientSetManagersInput struct {
	ManagerGroups []string `json:"managerGroups"`
}

// ── 应用管理 ────────────────────────────────────────────────────────────────────

// APIAdminClients mirrors AdminClients: lists clients the current user may
// manage.
func (h *Handler) APIAdminClients(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	allClients, _ := h.st.ListClients(ctx)
	cur := h.currentUser(r)
	var clients []*store.OAuthClient
	for _, c := range allClients {
		if h.canManageClient(ctx, cur, c) {
			clients = append(clients, c)
		}
	}
	apiOK(w, http.StatusOK, toAdminClientDTOs(clients))
}

// APIAdminClientCreate mirrors AdminClientCreate. Instead of stashing the
// plaintext secret in a one-time ticket and redirecting, it returns the
// plaintext secret directly; only the hash is persisted.
func (h *Handler) APIAdminClientCreate(w http.ResponseWriter, r *http.Request) {
	var in adminClientCreateInput
	if !decodeJSON(w, r, &in) {
		return
	}

	name := strings.TrimSpace(in.Name)
	desc := strings.TrimSpace(in.Description)

	var uris []string
	for _, l := range strings.Split(in.RedirectURIs, "\n") {
		if u := strings.TrimSpace(l); u != "" {
			uris = append(uris, u)
		}
	}
	scopes := normalizeScopes(strings.Fields(in.Scopes))
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	ctx := r.Context()

	if name == "" {
		apiErr(w, http.StatusBadRequest, "validation", "应用名称不能为空")
		return
	}
	if len(uris) == 0 {
		apiErr(w, http.StatusBadRequest, "validation", "至少需要一个回调地址")
		return
	}
	for _, u := range uris {
		if !isAllowedAbsoluteURL(u) {
			apiErr(w, http.StatusBadRequest, "validation", "回调地址无效："+u)
			return
		}
	}

	clientID, secret, err := h.st.CreateClient(ctx, name, desc, uris, scopes)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			apiErr(w, http.StatusConflict, "conflict", "应用名称已存在，请换一个名称")
		} else {
			apiErr(w, http.StatusConflict, "conflict", "创建失败："+err.Error())
		}
		return
	}

	// Fetch the created client to get its internal UUID for linking.
	newClient, _ := h.st.GetClientByClientID(ctx, clientID)
	if newClient != nil {
		h.logAudit(ctx, h.currentUser(r), "create", "client", newClient.ID, name, "", marshalJSON(newClient))
	}

	apiOKFlash(w, http.StatusOK, map[string]any{
		"client":       toAdminClientDTO(newClient),
		"clientSecret": secret,
	}, "应用已创建")
}

// APIAdminClientDetail mirrors AdminClientDetail: returns the client, the
// issuer-based integration endpoints, the available groups for selectors and
// the client's current manager groups.
func (h *Handler) APIAdminClientDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	client, err := h.st.GetClientByID(ctx, id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "应用不存在")
		return
	}
	if !h.canManageClient(ctx, h.currentUser(r), client) {
		apiErr(w, http.StatusForbidden, "forbidden", "您没有权限管理此应用")
		return
	}
	allGroups, _ := h.st.ListUserGroups(ctx)
	apiOK(w, http.StatusOK, map[string]any{
		"client":        toAdminClientDTO(client),
		"integration":   h.adminClientIntegration(),
		"groups":        toAdminGroupDTOs(allGroups),
		"managerGroups": client.ManagerGroups,
	})
}

// APIAdminClientUpdate mirrors AdminClientUpdate.
func (h *Handler) APIAdminClientUpdate(w http.ResponseWriter, r *http.Request) {
	var in adminClientUpdateInput
	if !decodeJSON(w, r, &in) {
		return
	}

	id := r.PathValue("id")
	name := strings.TrimSpace(in.Name)
	desc := strings.TrimSpace(in.Description)
	baseAccess := strings.ToLower(strings.TrimSpace(in.BaseAccess))

	ctx := r.Context()
	// Check per-app manager permission.
	client0, err := h.st.GetClientByID(ctx, id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "应用不存在")
		return
	}
	if !h.canManageClient(ctx, h.currentUser(r), client0) {
		apiErr(w, http.StatusForbidden, "forbidden", "您没有权限管理此应用")
		return
	}

	var uris []string
	for _, l := range strings.Split(in.RedirectURIs, "\n") {
		if u := strings.TrimSpace(l); u != "" {
			uris = append(uris, u)
		}
	}
	scopes := normalizeScopes(strings.Fields(in.Scopes))
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	if baseAccess == "" {
		baseAccess = "user"
	}
	switch baseAccess {
	case "legacy", "user", "member", "admin", "none":
	default:
		apiErr(w, http.StatusBadRequest, "validation", "基础访问策略无效")
		return
	}
	allowedGroupsSet := map[string]bool{}
	var allowedGroups []string
	for _, g := range strings.Fields(strings.ToLower(in.AllowedGroups)) {
		if g == "" || allowedGroupsSet[g] {
			continue
		}
		allowedGroupsSet[g] = true
		allowedGroups = append(allowedGroups, g)
	}

	if name == "" {
		apiErr(w, http.StatusBadRequest, "validation", "名称不能为空")
		return
	}
	// Validate custom groups exist to avoid silent misconfiguration.
	groupSet := map[string]bool{}
	groups, err := h.st.ListUserGroups(ctx)
	if err != nil {
		apiErr(w, http.StatusConflict, "conflict", "分组查询失败")
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
				apiErr(w, http.StatusBadRequest, "validation", "未知分组："+g)
				return
			}
		}
	}
	if err := h.st.UpdateClient(ctx, id, name, desc, uris, scopes, baseAccess, allowedGroups); err != nil {
		msg := "更新失败"
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			msg = "应用名称已存在"
		}
		apiErr(w, http.StatusConflict, "conflict", msg)
		return
	}
	// client0 captured before update contains the before_state.
	h.logAudit(ctx, h.currentUser(r), "update", "client", id, client0.Name,
		marshalJSON(client0), marshalJSON(map[string]any{"name": name, "description": desc, "base_access": baseAccess, "allowed_groups": allowedGroups}))
	apiOKFlash(w, http.StatusOK, nil, "已更新")
}

// APIAdminClientResetSecret mirrors AdminClientResetSecret. Instead of stashing
// the new plaintext secret in a one-time ticket and redirecting, it returns the
// plaintext secret directly; only the hash is persisted.
func (h *Handler) APIAdminClientResetSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	client, err := h.st.GetClientByID(ctx, id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "应用不存在")
		return
	}
	if !h.canManageClient(ctx, h.currentUser(r), client) {
		apiErr(w, http.StatusForbidden, "forbidden", "您没有权限管理此应用")
		return
	}
	newSecret, err := h.st.ResetClientSecret(ctx, id)
	if err != nil {
		apiErr(w, http.StatusConflict, "conflict", "重置失败")
		return
	}

	h.logAudit(ctx, h.currentUser(r), "update", "client", id, client.Name,
		marshalJSON(map[string]string{"client_secret": "previous"}),
		marshalJSON(map[string]string{"client_secret": "reset"}))
	apiOKFlash(w, http.StatusOK, map[string]any{
		"clientSecret": newSecret,
	}, "应用密钥已重置，请立即保存（仅显示一次）。")
}

// APIAdminClientDelete mirrors AdminClientDelete.
func (h *Handler) APIAdminClientDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	existing, _ := h.st.GetClientByID(ctx, id)
	if err := h.st.DeleteClient(ctx, id); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "删除失败："+err.Error())
		return
	}
	if existing != nil {
		h.logAudit(ctx, h.currentUser(r), "delete", "client", id, existing.Name, marshalJSON(existing), "")
	}
	apiOKFlash(w, http.StatusOK, nil, "已删除")
}

// APIAdminClientSetManagers mirrors AdminClientSetManagers.
func (h *Handler) APIAdminClientSetManagers(w http.ResponseWriter, r *http.Request) {
	var in adminClientSetManagersInput
	if !decodeJSON(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()
	client, err := h.st.GetClientByID(ctx, id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "应用不存在")
		return
	}

	var groups []string
	seen := map[string]bool{}
	for _, g := range in.ManagerGroups {
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
			apiErr(w, http.StatusBadRequest, "validation", "未知分组："+g)
			return
		}
	}

	if err := h.st.UpdateClientManagerGroups(ctx, id, groups); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "保存失败："+err.Error())
		return
	}

	cur := h.currentUser(r)
	h.logAudit(ctx, cur, "update", "client", id, client.Name,
		marshalJSON(map[string]any{"manager_groups": client.ManagerGroups}),
		marshalJSON(map[string]any{"manager_groups": groups}))

	apiOKFlash(w, http.StatusOK, nil, "管理权限组已保存")
}
