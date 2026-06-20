package server

import (
	"net/http"
	"strings"
	"time"

	"transmtf.com/oidc/internal/store"
)

// registerAdminMiscAPIRoutes wires the JSON admin providers / roles /
// announcements / settings / audit-log API under /api/v1. It mirrors the
// server-rendered handlers in handlers_admin.go (AdminProviders*, AdminRoles*,
// AdminAnnouncements*, AdminSettings*, AdminAudit*) but speaks JSON.
//
// Auth guards match the HTML routes (server.go:556-570): provider routes need
// "manage_providers", role routes "manage_roles", announcement routes
// "manage_announcements", settings routes "manage_settings", and the audit-log
// routes require apiRequireAdmin.
//
// JSON-body and DELETE mutations are wrapped with requireAPICSRF. The multipart
// settings-icon upload verifies CSRF inside the handler (after parsing the
// multipart form). GET reads are unguarded for CSRF. The validation, store
// calls and audit logging are copied verbatim from the HTML handlers; only the
// input parsing (form→JSON / multipart) and output (redirect/render→apiOK/apiErr)
// change. Reused Chinese flash strings are preserved.
func registerAdminMiscAPIRoutes(mux *http.ServeMux, h *Handler) {
	// ── 登录方式 (manage_providers) ───────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/admin/providers",
		h.apiRequirePermission("manage_providers")(h.APIAdminProviders))
	mux.HandleFunc("POST /api/v1/admin/providers",
		h.apiRequirePermission("manage_providers")(h.requireAPICSRF(h.APIAdminProviderCreate)))
	mux.HandleFunc("GET /api/v1/admin/providers/{id}",
		h.apiRequirePermission("manage_providers")(h.APIAdminProviderDetail))
	mux.HandleFunc("PATCH /api/v1/admin/providers/{id}",
		h.apiRequirePermission("manage_providers")(h.requireAPICSRF(h.APIAdminProviderEdit)))
	mux.HandleFunc("POST /api/v1/admin/providers/{id}/toggle",
		h.apiRequirePermission("manage_providers")(h.requireAPICSRF(h.APIAdminProviderToggle)))
	mux.HandleFunc("DELETE /api/v1/admin/providers/{id}",
		h.apiRequirePermission("manage_providers")(h.requireAPICSRF(h.APIAdminProviderDelete)))

	// ── 角色管理 (manage_roles) ───────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/admin/roles",
		h.apiRequirePermission("manage_roles")(h.APIAdminRoles))
	mux.HandleFunc("POST /api/v1/admin/roles",
		h.apiRequirePermission("manage_roles")(h.requireAPICSRF(h.APIAdminRoleCreate)))
	mux.HandleFunc("DELETE /api/v1/admin/roles/{name}",
		h.apiRequirePermission("manage_roles")(h.requireAPICSRF(h.APIAdminRoleDelete)))

	// ── 应用公告 (manage_announcements) ───────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/admin/announcements",
		h.apiRequirePermission("manage_announcements")(h.APIAdminAnnouncements))
	mux.HandleFunc("POST /api/v1/admin/announcements/{clientid}",
		h.apiRequirePermission("manage_announcements")(h.requireAPICSRF(h.APIAdminAnnouncementSave)))

	// ── 站点设置 (manage_settings) ────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/admin/settings",
		h.apiRequirePermission("manage_settings")(h.APIAdminSettings))
	mux.HandleFunc("PATCH /api/v1/admin/settings",
		h.apiRequirePermission("manage_settings")(h.requireAPICSRF(h.APIAdminSettingsSave)))
	// CSRF for the multipart upload is verified inside the handler after the
	// multipart form is parsed (matching AdminSettingsUploadIcon).
	mux.HandleFunc("POST /api/v1/admin/settings/icon",
		h.apiRequirePermission("manage_settings")(h.APIAdminSettingsUploadIcon))

	// ── 审计日志 (apiRequireAdmin) ────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/admin/audit-logs",
		h.apiRequireAdmin(h.APIAdminAuditLogs))
	mux.HandleFunc("POST /api/v1/admin/audit-logs/{id}/rollback",
		h.apiRequireAdmin(h.requireAPICSRF(h.APIAdminAuditRollback)))
}

// ── DTOs ─────────────────────────────────────────────────────────────────────

// adminProviderDTO exposes an external identity provider's safe fields. It
// NEVER exposes the raw client_secret; instead clientSecretSet reports whether
// one is configured so the SPA can render a "leave blank to keep" hint.
type adminProviderDTO struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Slug             string   `json:"slug"`
	ProviderType     string   `json:"providerType"`
	Icon             string   `json:"icon"`
	ClientID         string   `json:"clientId"`
	ClientSecretSet  bool     `json:"clientSecretSet"`
	IssuerURL        string   `json:"issuerUrl"`
	AuthorizationURL string   `json:"authorizationUrl"`
	TokenURL         string   `json:"tokenUrl"`
	UserinfoURL      string   `json:"userinfoUrl"`
	Scopes           string   `json:"scopes"`
	ScopeList        []string `json:"scopeList"`
	Enabled          bool     `json:"enabled"`
	AutoRegister     bool     `json:"autoRegister"`
	CreatedAt        string   `json:"createdAt"`
}

func toAdminProviderDTO(p *store.OIDCProvider) *adminProviderDTO {
	if p == nil {
		return nil
	}
	return &adminProviderDTO{
		ID:               p.ID,
		Name:             p.Name,
		Slug:             p.Slug,
		ProviderType:     normalizeProviderType(p.ProviderType),
		Icon:             p.Icon,
		ClientID:         p.ClientID,
		ClientSecretSet:  p.ClientSecret != "",
		IssuerURL:        p.IssuerURL,
		AuthorizationURL: p.AuthorizationURL,
		TokenURL:         p.TokenURL,
		UserinfoURL:      p.UserinfoURL,
		Scopes:           p.Scopes,
		ScopeList:        strings.Fields(p.Scopes),
		Enabled:          p.Enabled,
		AutoRegister:     p.AutoRegister,
		CreatedAt:        p.CreatedAt.Format(time.RFC3339),
	}
}

func toAdminProviderDTOs(ps []*store.OIDCProvider) []*adminProviderDTO {
	out := make([]*adminProviderDTO, 0, len(ps))
	for _, p := range ps {
		out = append(out, toAdminProviderDTO(p))
	}
	return out
}

// adminRoleDTO exposes a custom role's safe fields.
type adminRoleDTO struct {
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Permissions []string `json:"permissions"`
	CreatedAt   string   `json:"createdAt"`
}

func toAdminRoleDTO(r *store.CustomRole) *adminRoleDTO {
	if r == nil {
		return nil
	}
	return &adminRoleDTO{
		Name:        r.Name,
		Label:       r.Label,
		Permissions: r.Permissions,
		CreatedAt:   r.CreatedAt.Format(time.RFC3339),
	}
}

func toAdminRoleDTOs(rs []*store.CustomRole) []*adminRoleDTO {
	out := make([]*adminRoleDTO, 0, len(rs))
	for _, r := range rs {
		out = append(out, toAdminRoleDTO(r))
	}
	return out
}

// adminAuditDTO exposes an audit-log entry's safe fields (including the
// before/after JSON states the HTML log table renders).
type adminAuditDTO struct {
	ID           string `json:"id"`
	OperatorID   string `json:"operatorId"`
	OperatorName string `json:"operatorName"`
	OperatorRole string `json:"operatorRole"`
	Action       string `json:"action"`
	EntityType   string `json:"entityType"`
	EntityID     string `json:"entityId"`
	EntityName   string `json:"entityName"`
	BeforeState  string `json:"beforeState"`
	AfterState   string `json:"afterState"`
	CreatedAt    string `json:"createdAt"`
}

func toAdminAuditDTO(al *store.AuditLog) *adminAuditDTO {
	if al == nil {
		return nil
	}
	return &adminAuditDTO{
		ID:           al.ID,
		OperatorID:   al.OperatorID,
		OperatorName: al.OperatorName,
		OperatorRole: al.OperatorRole,
		Action:       al.Action,
		EntityType:   al.EntityType,
		EntityID:     al.EntityID,
		EntityName:   al.EntityName,
		BeforeState:  redactAuditState(al.BeforeState),
		AfterState:   redactAuditState(al.AfterState),
		CreatedAt:    al.CreatedAt.Format(time.RFC3339),
	}
}

func toAdminAuditDTOs(ls []*store.AuditLog) []*adminAuditDTO {
	out := make([]*adminAuditDTO, 0, len(ls))
	for _, al := range ls {
		out = append(out, toAdminAuditDTO(al))
	}
	return out
}

// adminMiscSettingsSecretKeys lists settings that hold a credential. Their raw
// value is never returned by the GET endpoint; only a "<key>Set" boolean is.
var adminMiscSettingsSecretKeys = []string{"smtp_pass", "resend_api_key"}

// ── Input bodies ───────────────────────────────────────────────────────────────

// adminProviderCreateInput mirrors the form fields read by AdminProviderCreate.
type adminProviderCreateInput struct {
	Name             string `json:"name"`
	Slug             string `json:"slug"`
	ProviderType     string `json:"providerType"`
	Icon             string `json:"icon"`
	ClientID         string `json:"clientId"`
	ClientSecret     string `json:"clientSecret"`
	IssuerURL        string `json:"issuerUrl"`
	AuthorizationURL string `json:"authorizationUrl"`
	TokenURL         string `json:"tokenUrl"`
	UserinfoURL      string `json:"userinfoUrl"`
	Scopes           string `json:"scopes"`
}

// adminProviderEditInput mirrors the form fields read by AdminProviderEdit.
// ClientID / ClientSecret left blank keep the existing values (matching the
// HTML handler's behaviour).
type adminProviderEditInput struct {
	Name             string `json:"name"`
	ProviderType     string `json:"providerType"`
	Icon             string `json:"icon"`
	ClientID         string `json:"clientId"`
	ClientSecret     string `json:"clientSecret"`
	IssuerURL        string `json:"issuerUrl"`
	AuthorizationURL string `json:"authorizationUrl"`
	TokenURL         string `json:"tokenUrl"`
	UserinfoURL      string `json:"userinfoUrl"`
	Scopes           string `json:"scopes"`
}

// adminRoleCreateInput mirrors the form fields read by AdminRoleCreate.
type adminRoleCreateInput struct {
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Permissions []string `json:"permissions"`
}

// adminAnnouncementSaveInput mirrors the content field of AdminAnnouncementSave.
type adminAnnouncementSaveInput struct {
	Content string `json:"content"`
}

// adminSettingsSaveInput mirrors the settings keys read by AdminSettingsSave.
// Pointer fields distinguish "absent" from "empty": secret fields (SMTPPass,
// ResendAPIKey) are only written when non-nil and non-empty, matching the HTML
// handler which only overwrites when a new value is supplied.
type adminSettingsSaveInput struct {
	SiteName              *string `json:"site_name"`
	ContactEmail          *string `json:"contact_email"`
	SiteIconURL           *string `json:"site_icon_url"`
	AnnZH                 *string `json:"ann_zh"`
	AnnEN                 *string `json:"ann_en"`
	TosContent            *string `json:"tos_content"`
	PrivacyContent        *string `json:"privacy_content"`
	EmailProvider         *string `json:"email_provider"`
	SMTPHost              *string `json:"smtp_host"`
	SMTPPort              *string `json:"smtp_port"`
	SMTPUser              *string `json:"smtp_user"`
	SMTPFrom              *string `json:"smtp_from"`
	ResendFrom            *string `json:"resend_from"`
	EmailTplWelcome       *string `json:"email_tpl_welcome"`
	EmailTplPasswordReset *string `json:"email_tpl_password_reset"`
	SMTPPass              *string `json:"smtp_pass"`
	ResendAPIKey          *string `json:"resend_api_key"`
}

// ── 登录方式 ────────────────────────────────────────────────────────────────────

// APIAdminProviders mirrors AdminProviders: lists all identity providers.
func (h *Handler) APIAdminProviders(w http.ResponseWriter, r *http.Request) {
	providers, _ := h.st.ListOIDCProviders(r.Context())
	for _, p := range providers {
		p.ProviderType = normalizeProviderType(p.ProviderType)
	}
	apiOK(w, http.StatusOK, toAdminProviderDTOs(providers))
}

// APIAdminProviderDetail mirrors AdminProviderEditPage: a single provider for editing.
func (h *Handler) APIAdminProviderDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	p, err := h.st.GetOIDCProviderByID(ctx, id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "提供商不存在")
		return
	}
	p.ProviderType = normalizeProviderType(p.ProviderType)
	apiOK(w, http.StatusOK, toAdminProviderDTO(p))
}

// APIAdminProviderCreate mirrors AdminProviderCreate.
func (h *Handler) APIAdminProviderCreate(w http.ResponseWriter, r *http.Request) {
	var in adminProviderCreateInput
	if !decodeJSON(w, r, &in) {
		return
	}
	name := strings.TrimSpace(in.Name)
	slug := strings.TrimSpace(in.Slug)
	providerType := normalizeProviderType(in.ProviderType)
	icon := strings.TrimSpace(in.Icon)
	clientID := strings.TrimSpace(in.ClientID)
	clientSecret := in.ClientSecret
	issuerURL := strings.TrimSpace(in.IssuerURL)
	authorizationURL := strings.TrimSpace(in.AuthorizationURL)
	tokenURL := strings.TrimSpace(in.TokenURL)
	userinfoURL := strings.TrimSpace(in.UserinfoURL)
	scopes := normalizeScopes(strings.Fields(strings.TrimSpace(in.Scopes)))
	autoRegister := false
	if len(scopes) == 0 {
		scopes = defaultProviderScopes(providerType)
	}

	if name == "" || slug == "" || clientID == "" || clientSecret == "" {
		apiErr(w, http.StatusBadRequest, "validation", "请完整填写登录方式信息")
		return
	}
	if !providerSlugRe.MatchString(slug) {
		apiErr(w, http.StatusBadRequest, "validation", "路径标识只能包含小写字母、数字和连字符")
		return
	}
	if msg := validateProviderProtocolConfig(providerType, issuerURL, authorizationURL, tokenURL, userinfoURL, scopes); msg != "" {
		apiErr(w, http.StatusBadRequest, "validation", msg)
		return
	}
	issuerURL, authorizationURL, tokenURL, userinfoURL = normalizeProviderEndpoints(
		providerType, issuerURL, authorizationURL, tokenURL, userinfoURL)

	ctx := r.Context()
	if err := h.st.CreateOIDCProvider(ctx, name, slug, providerType, icon, clientID, clientSecret, issuerURL, authorizationURL, tokenURL, userinfoURL, strings.Join(scopes, " "), autoRegister); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "创建失败："+err.Error())
		return
	}
	var created *store.OIDCProvider
	if p, _ := h.st.GetOIDCProviderBySlug(ctx, slug); p != nil {
		created = p
		h.logAudit(ctx, h.currentUser(r), "create", "provider", p.ID, p.Name, "", marshalJSON(p))
	}
	apiOKFlash(w, http.StatusOK, toAdminProviderDTO(created), "登录方式已添加")
}

// APIAdminProviderEdit mirrors AdminProviderEdit.
func (h *Handler) APIAdminProviderEdit(w http.ResponseWriter, r *http.Request) {
	var in adminProviderEditInput
	if !decodeJSON(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()
	p, err := h.st.GetOIDCProviderByID(ctx, id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "提供商不存在")
		return
	}

	name := strings.TrimSpace(in.Name)
	providerType := normalizeProviderType(in.ProviderType)
	icon := strings.TrimSpace(in.Icon)
	clientID := strings.TrimSpace(in.ClientID)
	clientSecret := in.ClientSecret
	issuerURL := strings.TrimSpace(in.IssuerURL)
	authorizationURL := strings.TrimSpace(in.AuthorizationURL)
	tokenURL := strings.TrimSpace(in.TokenURL)
	userinfoURL := strings.TrimSpace(in.UserinfoURL)
	scopes := normalizeScopes(strings.Fields(strings.TrimSpace(in.Scopes)))
	autoRegister := p.AutoRegister

	if len(scopes) == 0 {
		scopes = defaultProviderScopes(providerType)
	}

	if name == "" {
		apiErr(w, http.StatusBadRequest, "validation", "名称不能为空")
		return
	}
	if msg := validateProviderProtocolConfig(providerType, issuerURL, authorizationURL, tokenURL, userinfoURL, scopes); msg != "" {
		apiErr(w, http.StatusBadRequest, "validation", msg)
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
		apiErr(w, http.StatusConflict, "conflict", "更新失败: "+err.Error())
		return
	}
	h.logAudit(ctx, h.currentUser(r), "update", "provider", p.ID, p.Name, marshalJSON(p),
		marshalJSON(map[string]any{"name": name, "provider_type": providerType, "enabled": p.Enabled}))
	updated, _ := h.st.GetOIDCProviderByID(ctx, id)
	apiOKFlash(w, http.StatusOK, toAdminProviderDTO(updated), "已更新")
}

// APIAdminProviderToggle mirrors AdminProviderToggle.
func (h *Handler) APIAdminProviderToggle(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	p, err := h.st.GetOIDCProviderByID(ctx, id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "未找到")
		return
	}
	if err := h.st.UpdateOIDCProvider(ctx, p.ID, p.Name, normalizeProviderType(p.ProviderType), p.Icon, p.ClientID, p.ClientSecret, p.IssuerURL, p.AuthorizationURL, p.TokenURL, p.UserinfoURL, p.Scopes, !p.Enabled, p.AutoRegister); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "操作失败："+err.Error())
		return
	}
	h.logAudit(ctx, h.currentUser(r), "update", "provider", p.ID, p.Name,
		marshalJSON(map[string]any{"enabled": p.Enabled}),
		marshalJSON(map[string]any{"enabled": !p.Enabled}))
	apiOKFlash(w, http.StatusOK, map[string]any{"enabled": !p.Enabled}, "已更新")
}

// APIAdminProviderDelete mirrors AdminProviderDelete.
func (h *Handler) APIAdminProviderDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	existing, _ := h.st.GetOIDCProviderByID(ctx, id)
	if err := h.st.DeleteOIDCProvider(ctx, id); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "删除失败："+err.Error())
		return
	}
	if existing != nil {
		h.logAudit(ctx, h.currentUser(r), "delete", "provider", id, existing.Name, marshalJSON(existing), "")
	}
	apiOKFlash(w, http.StatusOK, nil, "已删除")
}

// ── 角色管理 ────────────────────────────────────────────────────────────────────

// APIAdminRoles mirrors AdminRoles: custom roles plus the permission catalog.
func (h *Handler) APIAdminRoles(w http.ResponseWriter, r *http.Request) {
	roles, _ := h.st.ListCustomRoles(r.Context())
	apiOK(w, http.StatusOK, map[string]any{
		"roles":          toAdminRoleDTOs(roles),
		"allPermissions": allPermissions,
	})
}

// APIAdminRoleCreate mirrors AdminRoleCreate.
func (h *Handler) APIAdminRoleCreate(w http.ResponseWriter, r *http.Request) {
	var in adminRoleCreateInput
	if !decodeJSON(w, r, &in) {
		return
	}
	name := strings.TrimSpace(strings.ToLower(in.Name))
	label := strings.TrimSpace(in.Label)
	permissions := in.Permissions
	ctx := r.Context()

	if name == "" {
		apiErr(w, http.StatusBadRequest, "validation", "角色名称不能为空")
		return
	}
	if err := h.st.CreateCustomRole(ctx, name, label, permissions); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "创建失败："+err.Error())
		return
	}
	var created *store.CustomRole
	if r2, _ := h.st.GetCustomRole(ctx, name); r2 != nil {
		created = r2
		h.logAudit(ctx, h.currentUser(r), "create", "role", r2.Name, r2.Label, "", marshalJSON(r2))
	}
	apiOKFlash(w, http.StatusOK, toAdminRoleDTO(created), "角色已创建")
}

// APIAdminRoleDelete mirrors AdminRoleDelete.
func (h *Handler) APIAdminRoleDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	existing, _ := h.st.GetCustomRole(r.Context(), name)
	if err := h.st.DeleteCustomRole(r.Context(), name); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "删除失败："+err.Error())
		return
	}
	if existing != nil {
		h.logAudit(r.Context(), h.currentUser(r), "delete", "role", existing.Name, existing.Label, marshalJSON(existing), "")
	}
	apiOKFlash(w, http.StatusOK, nil, "已删除")
}

// ── 应用公告 ────────────────────────────────────────────────────────────────────

// adminAnnouncementDTO pairs a manageable client with its current announcement.
type adminAnnouncementDTO struct {
	ID           string `json:"id"`
	ClientID     string `json:"clientId"`
	Name         string `json:"name"`
	Announcement string `json:"announcement"`
}

// APIAdminAnnouncements mirrors AdminAnnouncements: clients the current user can
// manage plus their announcement content.
func (h *Handler) APIAdminAnnouncements(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clients, _ := h.st.ListClients(ctx)
	cur := h.currentUser(r)
	items := make([]*adminAnnouncementDTO, 0, len(clients))
	for _, c := range clients {
		if !h.canManageClient(ctx, cur, c) {
			continue
		}
		items = append(items, &adminAnnouncementDTO{
			ID:           c.ID,
			ClientID:     c.ClientID,
			Name:         c.Name,
			Announcement: h.st.GetClientAnnouncement(ctx, c.ClientID),
		})
	}
	apiOK(w, http.StatusOK, items)
}

// APIAdminAnnouncementSave mirrors AdminAnnouncementSave.
func (h *Handler) APIAdminAnnouncementSave(w http.ResponseWriter, r *http.Request) {
	var in adminAnnouncementSaveInput
	if !decodeJSON(w, r, &in) {
		return
	}
	clientID := r.PathValue("clientid")
	content := in.Content
	ctx := r.Context()
	client, err := h.st.GetClientByClientID(ctx, clientID)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "应用不存在")
		return
	}
	// Verify the current user is authorized to manage this specific client.
	if !h.canManageClient(ctx, h.currentUser(r), client) {
		apiErr(w, http.StatusForbidden, "forbidden", "您没有权限管理此应用的公告")
		return
	}
	existingAnn := h.st.GetClientAnnouncement(ctx, clientID)
	if err := h.st.SetClientAnnouncement(ctx, clientID, content); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "保存失败")
		return
	}
	h.logAudit(ctx, h.currentUser(r), "update", "announcement", clientID, clientID,
		marshalJSON(map[string]string{"client_id": clientID, "content": existingAnn}),
		marshalJSON(map[string]string{"client_id": clientID, "content": content}))
	apiOKFlash(w, http.StatusOK, nil, "公告已保存")
}

// ── 站点设置 ────────────────────────────────────────────────────────────────────

// APIAdminSettings mirrors AdminSettings: returns the editable settings map.
// Credential values (smtp_pass, resend_api_key) are never echoed back; a
// "<key>Set" boolean reports whether one is configured instead.
func (h *Handler) APIAdminSettings(w http.ResponseWriter, r *http.Request) {
	cfg := h.st.GetAllSettings(r.Context())
	out := make(map[string]any, len(cfg)+len(adminMiscSettingsSecretKeys))
	secret := make(map[string]bool, len(adminMiscSettingsSecretKeys))
	for _, k := range adminMiscSettingsSecretKeys {
		secret[k] = true
	}
	for k, v := range cfg {
		if secret[k] {
			out[k+"Set"] = v != ""
			continue
		}
		out[k] = v
	}
	// Ensure the secret "<key>Set" flags exist even when the key is absent.
	for _, k := range adminMiscSettingsSecretKeys {
		if _, ok := out[k+"Set"]; !ok {
			out[k+"Set"] = false
		}
	}
	apiOK(w, http.StatusOK, out)
}

// APIAdminSettingsSave mirrors AdminSettingsSave.
func (h *Handler) APIAdminSettingsSave(w http.ResponseWriter, r *http.Request) {
	var in adminSettingsSaveInput
	if !decodeJSON(w, r, &in) {
		return
	}
	ctx := r.Context()
	oldSettings := h.st.GetAllSettings(ctx)
	// Plain (non-secret) keys: written when the field is present in the body.
	plain := []struct {
		key string
		val *string
	}{
		{"site_name", in.SiteName},
		{"contact_email", in.ContactEmail},
		{"site_icon_url", in.SiteIconURL},
		{"ann_zh", in.AnnZH},
		{"ann_en", in.AnnEN},
		{"tos_content", in.TosContent},
		{"privacy_content", in.PrivacyContent},
		{"email_provider", in.EmailProvider},
		{"smtp_host", in.SMTPHost},
		{"smtp_port", in.SMTPPort},
		{"smtp_user", in.SMTPUser},
		{"smtp_from", in.SMTPFrom},
		{"resend_from", in.ResendFrom},
		{"email_tpl_welcome", in.EmailTplWelcome},
		{"email_tpl_password_reset", in.EmailTplPasswordReset},
	}
	newSettings := make(map[string]string, len(plain)+len(adminMiscSettingsSecretKeys))
	for _, kv := range plain {
		if kv.val == nil {
			continue
		}
		newSettings[kv.key] = *kv.val
		_ = h.st.SetSetting(ctx, kv.key, *kv.val)
	}
	// 密码/密钥字段：只有提供了新值才覆盖。
	secrets := []struct {
		key string
		val *string
	}{
		{"smtp_pass", in.SMTPPass},
		{"resend_api_key", in.ResendAPIKey},
	}
	for _, kv := range secrets {
		if kv.val != nil && *kv.val != "" {
			newSettings[kv.key] = *kv.val
			_ = h.st.SetSetting(ctx, kv.key, *kv.val)
		}
	}
	h.logAudit(ctx, h.currentUser(r), "update", "setting", "site", "站点设置",
		marshalJSON(oldSettings), marshalJSON(newSettings))
	apiOKFlash(w, http.StatusOK, nil, "设置已保存")
}

// APIAdminSettingsUploadIcon mirrors AdminSettingsUploadIcon (multipart). CSRF
// is verified inside the handler after the multipart form is parsed.
func (h *Handler) APIAdminSettingsUploadIcon(w http.ResponseWriter, r *http.Request) {
	// Limit upload size to 5 MB.
	r.Body = http.MaxBytesReader(w, r.Body, MemberAdminImageOpts.MaxBytes)
	if err := r.ParseMultipartForm(MemberAdminImageOpts.MaxBytes); err != nil {
		apiErr(w, http.StatusRequestEntityTooLarge, "too_large", "文件过大（最大5MB）")
		return
	}
	if !h.verifyAPICSRF(r) {
		apiCSRFFailed(w)
		return
	}
	file, _, err := r.FormFile("icon_file")
	if err != nil {
		apiErr(w, http.StatusBadRequest, "validation", "未选择文件")
		return
	}
	defer file.Close()

	localURL, err := saveUploadedImage(file, "site", "icon", MemberAdminImageOpts)
	if err != nil {
		apiErr(w, http.StatusBadRequest, "validation", err.Error())
		return
	}
	// Clean up legacy favicons in CWD (pre-migration artifacts).
	removeLegacyFavicons("")

	ctx := r.Context()
	oldURL := h.st.GetSetting(ctx, "site_icon_url")
	_ = h.st.SetSetting(ctx, "site_icon_url", localURL)
	h.logAudit(ctx, h.currentUser(r), "update", "setting", "site_icon_url", "site_icon_url",
		marshalJSON(map[string]string{"site_icon_url": oldURL}),
		marshalJSON(map[string]string{"site_icon_url": localURL}))

	apiOKFlash(w, http.StatusOK, map[string]any{"iconUrl": localURL}, "图标已上传")
}

// ── 审计日志 ────────────────────────────────────────────────────────────────────

// APIAdminAuditLogs mirrors AdminAuditLogs: filtered, paginated audit log.
func (h *Handler) APIAdminAuditLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AuditLogFilter{
		OperatorID: strings.TrimSpace(q.Get("operator_id")),
		EntityType: strings.TrimSpace(q.Get("entity_type")),
		Action:     strings.TrimSpace(q.Get("action")),
		Search:     strings.TrimSpace(q.Get("q")),
	}
	if v := strings.TrimSpace(q.Get("from")); v != "" {
		if t, err := time.Parse("2006-01-02", v); err == nil {
			f.From = &t
		}
	}
	if v := strings.TrimSpace(q.Get("to")); v != "" {
		if t, err := time.Parse("2006-01-02", v); err == nil {
			tEnd := t.Add(24 * time.Hour)
			f.To = &tEnd
		}
	}
	pageSize := parsePageSize(q.Get("page_size"), 50, []int{20, 50, 100, 200})
	page := parsePage(q.Get("page"))
	f.Limit = pageSize
	f.Offset = (page - 1) * pageSize

	logs, total, _ := h.st.ListAuditLogsPaged(r.Context(), f)
	pages := (total + pageSize - 1) / pageSize
	if pages < 1 {
		pages = 1
	}
	apiOK(w, http.StatusOK, map[string]any{
		"logs":         toAdminAuditDTOs(logs),
		"total":        total,
		"page":         page,
		"pages":        pages,
		"pageSize":     pageSize,
		"pageSizeOpts": []int{20, 50, 100, 200},
		"rollbackDays": 3,
		"filters": map[string]any{
			"q":          f.Search,
			"entityType": f.EntityType,
			"action":     f.Action,
			"operatorId": f.OperatorID,
			"from":       q.Get("from"),
			"to":         q.Get("to"),
		},
	})
}

// APIAdminAuditRollback mirrors AdminAuditRollback.
func (h *Handler) APIAdminAuditRollback(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	al, err := h.st.GetAuditLog(ctx, id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "审计记录不存在")
		return
	}
	// Enforce 3-day rollback window.
	if time.Since(al.CreatedAt) > 3*24*time.Hour {
		apiErr(w, http.StatusBadRequest, "validation", "只能回滚 3 天内的操作")
		return
	}

	if err := h.rollback(ctx, al); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "回滚失败："+err.Error())
		return
	}

	// Record the rollback itself as an audit entry.
	cur := h.currentUser(r)
	h.logAudit(ctx, cur, "update", al.EntityType, al.EntityID, al.EntityName,
		"", marshalJSON(map[string]string{"rollback_of": al.ID}))

	apiOKFlash(w, http.StatusOK, nil, "回滚成功")
}
