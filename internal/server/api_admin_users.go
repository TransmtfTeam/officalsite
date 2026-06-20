package server

import (
	"context"
	"net/http"
	"strings"
	"time"

	"transmtf.com/oidc/internal/store"
)

// registerAdminUsersAPIRoutes wires the JSON admin user/group API under /api/v1.
// It mirrors the server-rendered admin handlers (handlers_admin.go,
// handlers_passkey.go) but speaks JSON. Auth guards match the HTML routes
// (server.go:516-566): the dashboard requires apiRequireAdmin, user routes
// require the "manage_users" permission, and group + user-group routes require
// "manage_groups".
//
// JSON-body and DELETE mutations are wrapped with requireAPICSRF. GET reads are
// not. The validation, store calls and audit logging are copied verbatim from
// the HTML handlers; only input parsing (form→JSON) and output (redirect/render
// →apiOK/apiErr) change.
func registerAdminUsersAPIRoutes(mux *http.ServeMux, h *Handler) {
	// ── 管理面板 (apiRequireAdmin) ────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/admin/dashboard",
		h.apiRequireAdmin(h.APIAdminDashboard))

	// ── 用户管理 (manage_users) ───────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/admin/users",
		h.apiRequirePermission("manage_users")(h.APIAdminUsers))
	mux.HandleFunc("POST /api/v1/admin/users",
		h.apiRequirePermission("manage_users")(h.requireAPICSRF(h.APIAdminUserCreate)))
	mux.HandleFunc("GET /api/v1/admin/users/{id}",
		h.apiRequirePermission("manage_users")(h.APIAdminUserDetail))
	mux.HandleFunc("PATCH /api/v1/admin/users/{id}",
		h.apiRequirePermission("manage_users")(h.requireAPICSRF(h.APIAdminUserUpdate)))
	mux.HandleFunc("DELETE /api/v1/admin/users/{id}",
		h.apiRequirePermission("manage_users")(h.requireAPICSRF(h.APIAdminUserDelete)))
	mux.HandleFunc("POST /api/v1/admin/users/{id}/reset-password",
		h.apiRequirePermission("manage_users")(h.requireAPICSRF(h.APIAdminUserResetPassword)))
	mux.HandleFunc("POST /api/v1/admin/users/{id}/disable-2fa",
		h.apiRequirePermission("manage_users")(h.requireAPICSRF(h.APIAdminUserDisable2FA)))
	mux.HandleFunc("POST /api/v1/admin/users/{id}/verify-email",
		h.apiRequirePermission("manage_users")(h.requireAPICSRF(h.APIAdminVerifyEmail)))
	mux.HandleFunc("POST /api/v1/admin/users/{id}/unverify-email",
		h.apiRequirePermission("manage_users")(h.requireAPICSRF(h.APIAdminUnverifyEmail)))
	mux.HandleFunc("DELETE /api/v1/admin/users/{id}/sessions/{sid}",
		h.apiRequirePermission("manage_users")(h.requireAPICSRF(h.APIAdminUserRevokeSession)))
	mux.HandleFunc("DELETE /api/v1/admin/users/{id}/tokens/{tid}",
		h.apiRequirePermission("manage_users")(h.requireAPICSRF(h.APIAdminUserRevokeToken)))
	mux.HandleFunc("DELETE /api/v1/admin/users/{id}/passkeys/{pkid}",
		h.apiRequirePermission("manage_users")(h.requireAPICSRF(h.APIAdminDeletePasskey)))

	// ── 用户分组关联 (manage_groups) ──────────────────────────────────────────────
	mux.HandleFunc("POST /api/v1/admin/users/{id}/groups",
		h.apiRequirePermission("manage_groups")(h.requireAPICSRF(h.APIAdminUserGroupAdd)))
	mux.HandleFunc("DELETE /api/v1/admin/users/{id}/groups/{gid}",
		h.apiRequirePermission("manage_groups")(h.requireAPICSRF(h.APIAdminUserGroupRemove)))

	// ── 分组管理 (manage_groups) ──────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/admin/groups",
		h.apiRequirePermission("manage_groups")(h.APIAdminGroups))
	mux.HandleFunc("POST /api/v1/admin/groups",
		h.apiRequirePermission("manage_groups")(h.requireAPICSRF(h.APIAdminGroupCreate)))
	mux.HandleFunc("GET /api/v1/admin/groups/{id}",
		h.apiRequirePermission("manage_groups")(h.APIAdminGroupDetail))
	mux.HandleFunc("DELETE /api/v1/admin/groups/{id}",
		h.apiRequirePermission("manage_groups")(h.requireAPICSRF(h.APIAdminGroupDelete)))
	mux.HandleFunc("POST /api/v1/admin/groups/{id}/members",
		h.apiRequirePermission("manage_groups")(h.requireAPICSRF(h.APIAdminGroupAddMember)))
	mux.HandleFunc("DELETE /api/v1/admin/groups/{id}/members/{uid}",
		h.apiRequirePermission("manage_groups")(h.requireAPICSRF(h.APIAdminGroupRemoveMember)))
}

// ── DTOs ─────────────────────────────────────────────────────────────────────

// adminGroupDTO exposes a user group's safe fields.
type adminGroupDTO struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Label     string `json:"label"`
	CreatedAt string `json:"createdAt"`
}

func toAdminGroupDTO(g *store.UserGroup) *adminGroupDTO {
	if g == nil {
		return nil
	}
	return &adminGroupDTO{
		ID:        g.ID,
		Name:      g.Name,
		Label:     g.Label,
		CreatedAt: g.CreatedAt.Format(time.RFC3339),
	}
}

func toAdminGroupDTOs(gs []*store.UserGroup) []*adminGroupDTO {
	out := make([]*adminGroupDTO, 0, len(gs))
	for _, g := range gs {
		out = append(out, toAdminGroupDTO(g))
	}
	return out
}

// adminUserSessionDTO exposes a session's safe fields (never the cookie value).
type adminUserSessionDTO struct {
	ID        string `json:"id"`
	CreatedAt string `json:"createdAt"`
	ExpiresAt string `json:"expiresAt"`
}

func toAdminUserSessionDTOs(ss []*store.Session) []*adminUserSessionDTO {
	out := make([]*adminUserSessionDTO, 0, len(ss))
	for _, s := range ss {
		out = append(out, &adminUserSessionDTO{
			ID:        s.ID,
			CreatedAt: s.CreatedAt.Format(time.RFC3339),
			ExpiresAt: s.ExpiresAt.Format(time.RFC3339),
		})
	}
	return out
}

// adminUserTokenDTO exposes an access/refresh token's safe fields (never the
// token value itself).
type adminUserTokenDTO struct {
	ID        string   `json:"id"`
	ClientID  string   `json:"clientId"`
	Scopes    []string `json:"scopes"`
	ExpiresAt string   `json:"expiresAt"`
}

func toAdminUserAccessTokenDTOs(ts []*store.AccessToken) []*adminUserTokenDTO {
	out := make([]*adminUserTokenDTO, 0, len(ts))
	for _, t := range ts {
		out = append(out, &adminUserTokenDTO{
			ID:        t.ID,
			ClientID:  t.ClientID,
			Scopes:    t.Scopes,
			ExpiresAt: t.ExpiresAt.Format(time.RFC3339),
		})
	}
	return out
}

func toAdminUserRefreshTokenDTOs(ts []*store.RefreshToken) []*adminUserTokenDTO {
	out := make([]*adminUserTokenDTO, 0, len(ts))
	for _, t := range ts {
		out = append(out, &adminUserTokenDTO{
			ID:        t.ID,
			ClientID:  t.ClientID,
			Scopes:    t.Scopes,
			ExpiresAt: t.ExpiresAt.Format(time.RFC3339),
		})
	}
	return out
}

// adminUserPasskeyDTO exposes a passkey's safe fields (never the credential
// blob).
type adminUserPasskeyDTO struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"createdAt"`
}

func toAdminUserPasskeyDTOs(cs []*store.PasskeyCredential) []*adminUserPasskeyDTO {
	out := make([]*adminUserPasskeyDTO, 0, len(cs))
	for _, c := range cs {
		out = append(out, &adminUserPasskeyDTO{
			ID:        c.ID,
			Name:      c.Name,
			CreatedAt: c.CreatedAt.Format(time.RFC3339),
		})
	}
	return out
}

// adminUserCustomRoleDTO exposes a custom role's safe fields.
type adminUserCustomRoleDTO struct {
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Permissions []string `json:"permissions"`
}

func toAdminUserCustomRoleDTOs(rs []*store.CustomRole) []*adminUserCustomRoleDTO {
	out := make([]*adminUserCustomRoleDTO, 0, len(rs))
	for _, r := range rs {
		out = append(out, &adminUserCustomRoleDTO{
			Name:        r.Name,
			Label:       r.Label,
			Permissions: r.Permissions,
		})
	}
	return out
}

// ── Input bodies ───────────────────────────────────────────────────────────────

// adminUserCreateInput mirrors the form fields read by AdminUserCreate.
type adminUserCreateInput struct {
	Email                 string `json:"email"`
	Password              string `json:"password"`
	DisplayName           string `json:"displayName"`
	Role                  string `json:"role"`
	RequirePasswordChange bool   `json:"requirePasswordChange"`
}

// adminUserUpdateInput mirrors the form fields read by AdminUserUpdate.
type adminUserUpdateInput struct {
	DisplayName string `json:"displayName"`
	Role        string `json:"role"`
	Active      bool   `json:"active"`
}

// adminUserDeleteInput mirrors the optional confirm_email field of AdminUserDelete.
type adminUserDeleteInput struct {
	ConfirmEmail string `json:"confirmEmail"`
}

// adminUserResetPasswordInput mirrors the form fields read by AdminUserResetPassword.
type adminUserResetPasswordInput struct {
	NewPassword           string `json:"newPassword"`
	RequirePasswordChange bool   `json:"requirePasswordChange"`
}

// adminUserRevokeTokenInput mirrors the "type" field of AdminUserRevokeToken.
type adminUserRevokeTokenInput struct {
	Type string `json:"type"`
}

// adminUserGroupAddInput mirrors the group_id field of AdminUserGroupAdd.
type adminUserGroupAddInput struct {
	GroupID string `json:"groupId"`
}

// adminGroupCreateInput mirrors the form fields read by AdminGroupCreate.
type adminGroupCreateInput struct {
	Name  string `json:"name"`
	Label string `json:"label"`
}

// adminGroupAddMemberInput mirrors the user_id field of AdminGroupAddMember.
type adminGroupAddMemberInput struct {
	UserID string `json:"userId"`
}

// ── 管理面板 ────────────────────────────────────────────────────────────────────

// APIAdminDashboard mirrors AdminDashboard: returns object counts.
func (h *Handler) APIAdminDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	apiOK(w, http.StatusOK, map[string]any{
		"users":     h.st.CountUsers(ctx),
		"clients":   h.st.CountClients(ctx),
		"projects":  h.st.CountProjects(ctx),
		"providers": h.st.CountOIDCProviders(ctx),
	})
}

// ── 用户管理 ────────────────────────────────────────────────────────────────────

// APIAdminUsers mirrors AdminUsers: paginated, filtered user list.
func (h *Handler) APIAdminUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.ListUsersFilter{
		Search: strings.TrimSpace(q.Get("q")),
		Role:   strings.TrimSpace(q.Get("role")),
	}
	if v := q.Get("active"); v == "1" {
		b := true
		f.Active = &b
	} else if v == "0" {
		b := false
		f.Active = &b
	}
	if v := q.Get("verified"); v == "1" {
		b := true
		f.EmailVerified = &b
	} else if v == "0" {
		b := false
		f.EmailVerified = &b
	}

	pageSize := parsePageSize(q.Get("page_size"), 50, []int{10, 20, 50, 100, 200})
	page := parsePage(q.Get("page"))
	f.Limit = pageSize
	f.Offset = (page - 1) * pageSize

	users, total, _ := h.st.ListUsersPaged(r.Context(), f)
	customRoles, _ := h.st.ListCustomRoles(r.Context())
	pages := (total + pageSize - 1) / pageSize
	if pages < 1 {
		pages = 1
	}
	apiOK(w, http.StatusOK, map[string]any{
		"users":        toUserDTOs(users),
		"total":        total,
		"page":         page,
		"pages":        pages,
		"pageSize":     pageSize,
		"pageSizeOpts": []int{10, 20, 50, 100, 200},
		"customRoles":  toAdminUserCustomRoleDTOs(customRoles),
		"isSysAdmin":   h.isSystemAdminUser(h.currentUser(r)),
		"filters": map[string]any{
			"q":        f.Search,
			"role":     f.Role,
			"active":   q.Get("active"),
			"verified": q.Get("verified"),
		},
	})
}

// APIAdminUserCreate mirrors AdminUserCreate.
func (h *Handler) APIAdminUserCreate(w http.ResponseWriter, r *http.Request) {
	var in adminUserCreateInput
	if !decodeJSON(w, r, &in) {
		return
	}
	email := strings.TrimSpace(in.Email)
	password := in.Password
	name := strings.TrimSpace(in.DisplayName)
	role := in.Role
	if role == "" {
		role = "user"
	}
	requireChange := in.RequirePasswordChange

	ctx := r.Context()
	if role == "admin" && !h.isSystemAdminUser(h.currentUser(r)) {
		apiErr(w, http.StatusForbidden, "forbidden", "仅系统管理员可以分配管理员角色")
		return
	}
	u, err := h.st.CreateUser(ctx, email, password, name, role)
	if err != nil {
		apiErr(w, http.StatusConflict, "conflict", "创建失败："+err.Error())
		return
	}
	if requireChange {
		if err := h.st.SetRequirePasswordChange(ctx, u.ID, true); err != nil {
			// 非致命错误：用户已创建，仅忽略强制改密标记写入失败。
			_ = err
		}
	}
	h.logAudit(ctx, h.currentUser(r), "create", "user", u.ID, u.Email, "", marshalJSON(u))
	apiOKFlash(w, http.StatusOK, toUserDTO(u), "已创建用户："+email)
}

// APIAdminUserDetail mirrors AdminUserDetail (non-modal mode): returns the user
// plus related sessions, tokens, passkeys and groups.
func (h *Handler) APIAdminUserDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	u, err := h.st.GetUserByID(ctx, id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	// 非系统管理员不能查看管理员账户的详情（含 session/token/passkey）。
	cur := h.currentUser(r)
	if u.IsAdmin() && !h.isSystemAdminUser(cur) {
		apiErr(w, http.StatusForbidden, "forbidden", "只有系统管理员可以查看管理员账户详情")
		return
	}

	sessions, _ := h.st.GetSessionsByUserID(ctx, id)
	accessTokens, _ := h.st.GetAccessTokensByUserID(ctx, id)
	refreshTokens, _ := h.st.GetRefreshTokensByUserID(ctx, id)
	passkeys, _ := h.st.GetPasskeyCredentialsByUserID(ctx, id)
	customRoles, _ := h.st.ListCustomRoles(ctx)
	userGroups, _ := h.st.GetUserGroups(ctx, id)

	apiOK(w, http.StatusOK, map[string]any{
		"user":          toUserDTO(u),
		"sessions":      toAdminUserSessionDTOs(sessions),
		"accessTokens":  toAdminUserAccessTokenDTOs(accessTokens),
		"refreshTokens": toAdminUserRefreshTokenDTOs(refreshTokens),
		"passkeys":      toAdminUserPasskeyDTOs(passkeys),
		"groups":        toAdminGroupDTOs(userGroups),
		"customRoles":   toAdminUserCustomRoleDTOs(customRoles),
		"isSysAdmin":    h.isSystemAdminUser(u),
	})
}

// APIAdminUserUpdate mirrors AdminUserUpdate.
func (h *Handler) APIAdminUserUpdate(w http.ResponseWriter, r *http.Request) {
	var in adminUserUpdateInput
	if !decodeJSON(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	name := strings.TrimSpace(in.DisplayName)
	role := in.Role
	active := in.Active

	ctx := r.Context()
	cur := h.currentUser(r)
	// 保护系统管理员账户
	targetUser, err := h.st.GetUserByID(ctx, id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	if targetUser.IsAdmin() && !h.isSystemAdminUser(cur) {
		apiErr(w, http.StatusForbidden, "forbidden", "不能修改管理员账户")
		return
	}
	if role == "admin" && !h.isSystemAdminUser(cur) {
		apiErr(w, http.StatusForbidden, "forbidden", "仅系统管理员可以分配管理员角色")
		return
	}
	if h.isSystemAdminUser(targetUser) {
		role = "admin"
		active = true
	}

	if err := h.st.UpdateUser(ctx, id, name, role, active); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "更新失败: "+err.Error())
		return
	}
	h.logAudit(ctx, cur, "update", "user", id, targetUser.Email,
		marshalJSON(targetUser),
		marshalJSON(map[string]any{"display_name": name, "role": role, "active": active}))
	apiOKFlash(w, http.StatusOK, nil, "已更新")
}

// APIAdminUserDelete mirrors AdminUserDelete.
func (h *Handler) APIAdminUserDelete(w http.ResponseWriter, r *http.Request) {
	var in adminUserDeleteInput
	if !decodeJSON(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	cur := h.currentUser(r)
	ctx := r.Context()

	targetUser, err := h.st.GetUserByID(ctx, id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	if targetUser.IsAdmin() && !h.isSystemAdminUser(cur) {
		apiErr(w, http.StatusForbidden, "forbidden", "不能修改管理员账户")
		return
	}
	if cur != nil && cur.ID == id {
		apiErr(w, http.StatusForbidden, "forbidden", "不能删除当前登录账户")
		return
	}
	// Optional secondary confirmation via modal: require matching email.
	if confirmEmail := strings.TrimSpace(in.ConfirmEmail); confirmEmail != "" {
		if !strings.EqualFold(confirmEmail, targetUser.Email) {
			apiErr(w, http.StatusBadRequest, "validation", "邮箱确认不匹配，删除已取消")
			return
		}
	}

	if err := h.st.DeleteUser(ctx, id); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "删除失败："+err.Error())
		return
	}

	// Best-effort remove local avatar file.
	removeUploadByBaseName("avatars", id)

	h.logAudit(ctx, cur, "delete", "user", id, targetUser.Email, marshalJSON(targetUser), "")
	apiOKFlash(w, http.StatusOK, nil, "已删除")
}

// APIAdminUserResetPassword mirrors AdminUserResetPassword.
func (h *Handler) APIAdminUserResetPassword(w http.ResponseWriter, r *http.Request) {
	var in adminUserResetPasswordInput
	if !decodeJSON(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	newPass := in.NewPassword
	requireChange := in.RequirePasswordChange
	ctx := r.Context()

	targetUser, err := h.st.GetUserByID(ctx, id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	// 仅系统管理员可修改其他管理员的密码。
	cur := h.currentUser(r)
	if targetUser.IsAdmin() && !h.isSystemAdminUser(cur) {
		apiErr(w, http.StatusForbidden, "forbidden", "不能修改管理员账户")
		return
	}

	if len(newPass) < 8 {
		apiErr(w, http.StatusBadRequest, "validation", "密码至少需要8位")
		return
	}
	if err := h.st.UpdatePassword(ctx, id, newPass); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "密码重置失败")
		return
	}
	if requireChange {
		_ = h.st.SetRequirePasswordChange(ctx, id, true)
	}
	go h.sendPasswordResetEmail(context.Background(), targetUser.Email, targetUser.DisplayName, newPass)
	h.logAudit(ctx, h.currentUser(r), "update", "user", id, targetUser.Email,
		marshalJSON(map[string]string{"action": "reset_password"}), "")
	apiOKFlash(w, http.StatusOK, nil, "密码已重置")
}

// APIAdminUserDisable2FA mirrors AdminUserDisable2FA.
func (h *Handler) APIAdminUserDisable2FA(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()

	targetUser, err := h.st.GetUserByID(ctx, id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	cur := h.currentUser(r)
	if targetUser.IsAdmin() && !h.isSystemAdminUser(cur) {
		apiErr(w, http.StatusForbidden, "forbidden", "不能修改管理员账户")
		return
	}

	if err := h.st.DisableTOTP(ctx, id); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "关闭双重验证失败")
		return
	}
	h.logAudit(ctx, h.currentUser(r), "update", "user", id, targetUser.Email,
		marshalJSON(map[string]string{"action": "disable_2fa"}), "")
	apiOKFlash(w, http.StatusOK, nil, "双重验证已关闭")
}

// APIAdminVerifyEmail mirrors AdminVerifyEmail.
func (h *Handler) APIAdminVerifyEmail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	targetUser, err := h.st.GetUserByID(ctx, id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	cur := h.currentUser(r)
	if targetUser.IsAdmin() && !h.isSystemAdminUser(cur) {
		apiErr(w, http.StatusForbidden, "forbidden", "不能修改管理员账户")
		return
	}
	if err := h.st.SetEmailVerified(ctx, id, true); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "邮箱验证失败")
		return
	}
	h.logAudit(ctx, h.currentUser(r), "update", "user", id, targetUser.Email,
		marshalJSON(map[string]bool{"email_verified": targetUser.EmailVerified}),
		marshalJSON(map[string]bool{"email_verified": true}))
	apiOKFlash(w, http.StatusOK, map[string]any{"emailVerified": true}, "邮箱已验证")
}

// APIAdminUnverifyEmail mirrors AdminUnverifyEmail.
func (h *Handler) APIAdminUnverifyEmail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	targetUser, err := h.st.GetUserByID(ctx, id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	cur := h.currentUser(r)
	if targetUser.IsAdmin() && !h.isSystemAdminUser(cur) {
		apiErr(w, http.StatusForbidden, "forbidden", "不能修改管理员账户")
		return
	}
	if err := h.st.SetEmailVerified(ctx, id, false); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "取消邮箱验证失败")
		return
	}
	h.logAudit(ctx, h.currentUser(r), "update", "user", id, targetUser.Email,
		marshalJSON(map[string]bool{"email_verified": targetUser.EmailVerified}),
		marshalJSON(map[string]bool{"email_verified": false}))
	apiOKFlash(w, http.StatusOK, map[string]any{"emailVerified": false}, "已设为未验证")
}

// APIAdminUserRevokeSession mirrors AdminUserRevokeSession.
func (h *Handler) APIAdminUserRevokeSession(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	sessID := r.PathValue("sid")
	targetUser, err := h.st.GetUserByID(r.Context(), userID)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	if targetUser.IsAdmin() && !h.isSystemAdminUser(h.currentUser(r)) {
		apiErr(w, http.StatusForbidden, "forbidden", "不能修改管理员账户")
		return
	}
	if err := h.st.DeleteSessionByIDAndUserID(r.Context(), sessID, userID); err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "会话不存在或已失效")
		return
	}
	h.logAudit(r.Context(), h.currentUser(r), "update", "user", userID, targetUser.Email,
		marshalJSON(map[string]string{"action": "revoke_session", "session_id": sessID}), "")
	apiOKFlash(w, http.StatusOK, nil, "会话已撤销")
}

// APIAdminUserRevokeToken mirrors AdminUserRevokeToken (type=access|refresh).
func (h *Handler) APIAdminUserRevokeToken(w http.ResponseWriter, r *http.Request) {
	var in adminUserRevokeTokenInput
	if !decodeJSON(w, r, &in) {
		return
	}
	userID := r.PathValue("id")
	tokenID := r.PathValue("tid")
	tokenType := in.Type
	ctx := r.Context()
	targetUser, err := h.st.GetUserByID(ctx, userID)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	if targetUser.IsAdmin() && !h.isSystemAdminUser(h.currentUser(r)) {
		apiErr(w, http.StatusForbidden, "forbidden", "不能修改管理员账户")
		return
	}
	if tokenType == "refresh" {
		if err := h.st.RevokeRefreshTokenByIDAndUserID(ctx, tokenID, userID); err != nil {
			apiErr(w, http.StatusNotFound, "not_found", "令牌不存在或已失效")
			return
		}
	} else {
		if err := h.st.RevokeAccessTokenByIDAndUserID(ctx, tokenID, userID); err != nil {
			apiErr(w, http.StatusNotFound, "not_found", "令牌不存在或已失效")
			return
		}
	}
	h.logAudit(ctx, h.currentUser(r), "update", "user", userID, targetUser.Email,
		marshalJSON(map[string]string{"action": "revoke_token", "token_id": tokenID, "type": tokenType}), "")
	apiOKFlash(w, http.StatusOK, nil, "令牌已撤销")
}

// APIAdminDeletePasskey mirrors AdminDeletePasskey (handlers_passkey.go).
func (h *Handler) APIAdminDeletePasskey(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	pkID := r.PathValue("pkid")
	ctx := r.Context()

	targetUser, err := h.st.GetUserByID(ctx, userID)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	cur := h.currentUser(r)
	if targetUser.IsAdmin() && !h.isSystemAdminUser(cur) {
		apiErr(w, http.StatusForbidden, "forbidden", "不能修改管理员账户")
		return
	}

	creds, err := h.st.GetPasskeyCredentialsByUserID(ctx, userID)
	if err != nil {
		apiErr(w, http.StatusConflict, "conflict", "删除失败")
		return
	}
	for _, c := range creds {
		if c.ID == pkID {
			if dbErr := h.st.DeletePasskeyCredential(ctx, pkID); dbErr != nil {
				apiErr(w, http.StatusConflict, "conflict", "删除失败")
				return
			}
			h.logAudit(ctx, h.currentUser(r), "update", "user", userID, targetUser.Email,
				marshalJSON(map[string]string{"passkey_id": pkID}),
				marshalJSON(map[string]string{"action": "delete_passkey", "passkey_id": pkID}))
			break
		}
	}
	apiOK(w, http.StatusOK, nil)
}

// ── 用户分组关联 ─────────────────────────────────────────────────────────────────

// APIAdminUserGroupAdd mirrors AdminUserGroupAdd.
func (h *Handler) APIAdminUserGroupAdd(w http.ResponseWriter, r *http.Request) {
	var in adminUserGroupAddInput
	if !decodeJSON(w, r, &in) {
		return
	}
	userID := r.PathValue("id")
	groupID := strings.TrimSpace(in.GroupID)
	if groupID == "" {
		apiErr(w, http.StatusBadRequest, "validation", "请选择分组")
		return
	}
	if _, err := h.st.GetUserGroupByID(r.Context(), groupID); err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "分组不存在")
		return
	}
	if err := h.st.AddUserToGroup(r.Context(), userID, groupID); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "添加分组失败："+err.Error())
		return
	}
	h.logAudit(r.Context(), h.currentUser(r), "update", "user", userID, userID,
		"", marshalJSON(map[string]string{"group_id": groupID, "action": "add_to_group"}))
	apiOKFlash(w, http.StatusOK, nil, "已加入分组")
}

// APIAdminUserGroupRemove mirrors AdminUserGroupRemove.
func (h *Handler) APIAdminUserGroupRemove(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	groupID := r.PathValue("gid")
	if err := h.st.RemoveUserFromGroup(r.Context(), userID, groupID); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "移除分组失败："+err.Error())
		return
	}
	h.logAudit(r.Context(), h.currentUser(r), "update", "user", userID, userID,
		marshalJSON(map[string]string{"group_id": groupID}), marshalJSON(map[string]string{"action": "remove_from_group"}))
	apiOKFlash(w, http.StatusOK, nil, "已移出分组")
}

// ── 分组管理 ────────────────────────────────────────────────────────────────────

// APIAdminGroups mirrors AdminGroups: lists all user groups.
func (h *Handler) APIAdminGroups(w http.ResponseWriter, r *http.Request) {
	groups, _ := h.st.ListUserGroups(r.Context())
	apiOK(w, http.StatusOK, toAdminGroupDTOs(groups))
}

// APIAdminGroupCreate mirrors AdminGroupCreate.
func (h *Handler) APIAdminGroupCreate(w http.ResponseWriter, r *http.Request) {
	var in adminGroupCreateInput
	if !decodeJSON(w, r, &in) {
		return
	}
	name := strings.TrimSpace(strings.ToLower(in.Name))
	label := strings.TrimSpace(in.Label)
	ctx := r.Context()

	if name == "" {
		apiErr(w, http.StatusBadRequest, "validation", "分组名称不能为空")
		return
	}
	if name == "admin" || name == "member" || name == "user" {
		apiErr(w, http.StatusBadRequest, "validation", "不能使用内置分组名称（管理员/成员/用户）")
		return
	}
	if err := h.st.CreateUserGroup(ctx, name, label); err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			apiErr(w, http.StatusConflict, "conflict", "分组名称已存在")
		} else {
			apiErr(w, http.StatusConflict, "conflict", "创建失败："+err.Error())
		}
		return
	}
	// Fetch newly created group for audit.
	var created *store.UserGroup
	if grps, _ := h.st.ListUserGroups(ctx); len(grps) > 0 {
		for _, g := range grps {
			if g.Name == name {
				created = g
				h.logAudit(ctx, h.currentUser(r), "create", "group", g.ID, g.Name, "", marshalJSON(g))
				break
			}
		}
	}
	apiOKFlash(w, http.StatusOK, toAdminGroupDTO(created), "分组已创建")
}

// APIAdminGroupDetail mirrors AdminGroupDetail: group plus members.
func (h *Handler) APIAdminGroupDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	g, err := h.st.GetUserGroupByID(ctx, id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "分组不存在")
		return
	}
	members, _ := h.st.GetGroupMembers(ctx, id)
	users, _ := h.st.ListUsers(ctx)
	apiOK(w, http.StatusOK, map[string]any{
		"group":   toAdminGroupDTO(g),
		"members": toUserDTOs(members),
		"users":   toUserDTOs(users),
	})
}

// APIAdminGroupDelete mirrors AdminGroupDelete.
func (h *Handler) APIAdminGroupDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, _ := h.st.GetUserGroupByID(r.Context(), id)
	if err := h.st.DeleteUserGroup(r.Context(), id); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "删除失败："+err.Error())
		return
	}
	if existing != nil {
		h.logAudit(r.Context(), h.currentUser(r), "delete", "group", id, existing.Name, marshalJSON(existing), "")
	}
	apiOKFlash(w, http.StatusOK, nil, "分组已删除")
}

// APIAdminGroupAddMember mirrors AdminGroupAddMember.
func (h *Handler) APIAdminGroupAddMember(w http.ResponseWriter, r *http.Request) {
	var in adminGroupAddMemberInput
	if !decodeJSON(w, r, &in) {
		return
	}
	groupID := r.PathValue("id")
	userID := in.UserID
	if err := h.st.AddUserToGroup(r.Context(), userID, groupID); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "添加失败："+err.Error())
		return
	}
	h.logAudit(r.Context(), h.currentUser(r), "update", "group", groupID, groupID,
		"", marshalJSON(map[string]string{"user_id": userID, "action": "add_member"}))
	apiOKFlash(w, http.StatusOK, nil, "成员已添加")
}

// APIAdminGroupRemoveMember mirrors AdminGroupRemoveMember.
func (h *Handler) APIAdminGroupRemoveMember(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
	userID := r.PathValue("uid")
	if err := h.st.RemoveUserFromGroup(r.Context(), userID, groupID); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "移除失败："+err.Error())
		return
	}
	h.logAudit(r.Context(), h.currentUser(r), "update", "group", groupID, groupID,
		marshalJSON(map[string]string{"user_id": userID}), marshalJSON(map[string]string{"action": "remove_member"}))
	apiOKFlash(w, http.StatusOK, nil, "成员已移除")
}
