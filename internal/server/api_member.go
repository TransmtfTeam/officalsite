package server

import (
	"net/http"
	"strings"
	"time"

	"transmtf.com/oidc/internal/store"
)

// registerMemberAPIRoutes wires the JSON member-panel API under /api/v1. It
// mirrors the server-rendered member handlers (handlers_member.go) but speaks
// JSON. Auth guards match the HTML routes (server.go): projects + links require
// the "manage_projects" permission, member user reads require "view_users", and
// the verify-email / toggle-status mutations require "moderate_users".
//
// JSON-body mutations are wrapped with requireAPICSRF. The two multipart upload
// handlers (project image, link icon) are NOT wrapped; they verify CSRF inside
// the handler after parsing the multipart form, exactly like the HTML versions.
func registerMemberAPIRoutes(mux *http.ServeMux, h *Handler) {
	// ── 项目管理 (manage_projects) ─────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/member/projects",
		h.apiRequirePermission("manage_projects")(h.APIMemberProjects))
	mux.HandleFunc("POST /api/v1/member/projects",
		h.apiRequirePermission("manage_projects")(h.requireAPICSRF(h.APIMemberProjectCreate)))
	mux.HandleFunc("GET /api/v1/member/projects/{id}",
		h.apiRequirePermission("manage_projects")(h.APIMemberProjectGet))
	mux.HandleFunc("PATCH /api/v1/member/projects/{id}",
		h.apiRequirePermission("manage_projects")(h.requireAPICSRF(h.APIMemberProjectUpdate)))
	mux.HandleFunc("DELETE /api/v1/member/projects/{id}",
		h.apiRequirePermission("manage_projects")(h.requireAPICSRF(h.APIMemberProjectDelete)))
	// Multipart: CSRF is verified inside the handler after ParseMultipartForm.
	mux.HandleFunc("POST /api/v1/member/projects/{id}/image",
		h.apiRequirePermission("manage_projects")(h.APIMemberProjectUploadImage))

	// ── 友情链接 (manage_projects) ─────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/member/links",
		h.apiRequirePermission("manage_projects")(h.APIMemberLinks))
	mux.HandleFunc("POST /api/v1/member/links",
		h.apiRequirePermission("manage_projects")(h.requireAPICSRF(h.APIMemberLinkCreate)))
	mux.HandleFunc("GET /api/v1/member/links/{id}",
		h.apiRequirePermission("manage_projects")(h.APIMemberLinkGet))
	mux.HandleFunc("PATCH /api/v1/member/links/{id}",
		h.apiRequirePermission("manage_projects")(h.requireAPICSRF(h.APIMemberLinkUpdate)))
	mux.HandleFunc("DELETE /api/v1/member/links/{id}",
		h.apiRequirePermission("manage_projects")(h.requireAPICSRF(h.APIMemberLinkDelete)))
	// Multipart: CSRF is verified inside the handler after ParseMultipartForm.
	mux.HandleFunc("POST /api/v1/member/links/{id}/icon",
		h.apiRequirePermission("manage_projects")(h.APIMemberLinkUploadIcon))

	// ── 用户管理 ───────────────────────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/member/users",
		h.apiRequirePermission("view_users")(h.APIMemberUsers))
	mux.HandleFunc("GET /api/v1/member/users/{id}",
		h.apiRequirePermission("view_users")(h.APIMemberUserDetail))
	mux.HandleFunc("POST /api/v1/member/users/{id}/verify-email",
		h.apiRequirePermission("moderate_users")(h.requireAPICSRF(h.APIMemberUserVerifyEmail)))
	mux.HandleFunc("POST /api/v1/member/users/{id}/toggle-status",
		h.apiRequirePermission("moderate_users")(h.requireAPICSRF(h.APIMemberUserToggleStatus)))
}

// ── DTOs ─────────────────────────────────────────────────────────────────────

type memberProjectDTO struct {
	ID        string `json:"id"`
	Slug      string `json:"slug"`
	NameZH    string `json:"nameZh"`
	NameEN    string `json:"nameEn"`
	DescZH    string `json:"descZh"`
	DescEN    string `json:"descEn"`
	Status    string `json:"status"`
	URL       string `json:"url"`
	Tags      string `json:"tags"`
	Featured  bool   `json:"featured"`
	SortOrder int    `json:"sortOrder"`
	ImageURL  string `json:"imageUrl"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

func toMemberProjectDTO(p *store.Project) *memberProjectDTO {
	if p == nil {
		return nil
	}
	return &memberProjectDTO{
		ID:        p.ID,
		Slug:      p.Slug,
		NameZH:    p.NameZH,
		NameEN:    p.NameEN,
		DescZH:    p.DescZH,
		DescEN:    p.DescEN,
		Status:    p.Status,
		URL:       p.URL,
		Tags:      p.Tags,
		Featured:  p.Featured,
		SortOrder: p.SortOrder,
		ImageURL:  p.ImageURL,
		CreatedAt: p.CreatedAt.Format(time.RFC3339),
		UpdatedAt: p.UpdatedAt.Format(time.RFC3339),
	}
}

func toMemberProjectDTOs(ps []*store.Project) []*memberProjectDTO {
	out := make([]*memberProjectDTO, 0, len(ps))
	for _, p := range ps {
		out = append(out, toMemberProjectDTO(p))
	}
	return out
}

type memberLinkDTO struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	Icon      string `json:"icon"`
	SortOrder int    `json:"sortOrder"`
	CreatedAt string `json:"createdAt"`
}

func toMemberLinkDTO(l *store.FriendLink) *memberLinkDTO {
	if l == nil {
		return nil
	}
	return &memberLinkDTO{
		ID:        l.ID,
		Name:      l.Name,
		URL:       l.URL,
		Icon:      l.Icon,
		SortOrder: l.SortOrder,
		CreatedAt: l.CreatedAt.Format(time.RFC3339),
	}
}

func toMemberLinkDTOs(ls []*store.FriendLink) []*memberLinkDTO {
	out := make([]*memberLinkDTO, 0, len(ls))
	for _, l := range ls {
		out = append(out, toMemberLinkDTO(l))
	}
	return out
}

type memberUserGroupDTO struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Label string `json:"label"`
}

func toMemberUserGroupDTOs(gs []*store.UserGroup) []*memberUserGroupDTO {
	out := make([]*memberUserGroupDTO, 0, len(gs))
	for _, g := range gs {
		out = append(out, &memberUserGroupDTO{
			ID:    g.ID,
			Name:  g.Name,
			Label: g.Label,
		})
	}
	return out
}

// memberProjectInput is the JSON body for project create/update. It mirrors the
// fields read by projectFromForm (handlers_member.go).
type memberProjectInput struct {
	Slug      string `json:"slug"`
	NameZH    string `json:"nameZh"`
	NameEN    string `json:"nameEn"`
	DescZH    string `json:"descZh"`
	DescEN    string `json:"descEn"`
	Status    string `json:"status"`
	URL       string `json:"url"`
	Tags      string `json:"tags"`
	Featured  bool   `json:"featured"`
	SortOrder int    `json:"sortOrder"`
}

// memberProjectFromInput builds a *store.Project applying the same trimming as
// projectFromForm (handlers_member.go).
func memberProjectFromInput(in memberProjectInput) *store.Project {
	return &store.Project{
		Slug:      strings.TrimSpace(in.Slug),
		NameZH:    strings.TrimSpace(in.NameZH),
		NameEN:    strings.TrimSpace(in.NameEN),
		DescZH:    in.DescZH,
		DescEN:    in.DescEN,
		Status:    in.Status,
		URL:       strings.TrimSpace(in.URL),
		Tags:      in.Tags,
		Featured:  in.Featured,
		SortOrder: in.SortOrder,
	}
}

// memberLinkInput is the JSON body for link create/update. It mirrors the fields
// read by MemberLinkCreate / MemberLinkUpdate (handlers_member.go).
type memberLinkInput struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	Icon      string `json:"icon"`
	SortOrder int    `json:"sortOrder"`
}

// ── 项目管理 ───────────────────────────────────────────────────────────────────

// APIMemberProjects mirrors MemberProjects: lists all projects.
func (h *Handler) APIMemberProjects(w http.ResponseWriter, r *http.Request) {
	projects, _ := h.st.ListProjects(r.Context())
	apiOK(w, http.StatusOK, toMemberProjectDTOs(projects))
}

// APIMemberProjectCreate mirrors MemberProjectCreate.
func (h *Handler) APIMemberProjectCreate(w http.ResponseWriter, r *http.Request) {
	var in memberProjectInput
	if !decodeJSON(w, r, &in) {
		return
	}
	p := memberProjectFromInput(in)
	ctx := r.Context()
	if err := h.st.CreateProject(ctx, p); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "创建失败："+err.Error())
		return
	}
	h.logAudit(ctx, h.currentUser(r), "create", "project", p.ID, p.NameZH, "", marshalJSON(p))
	apiOKFlash(w, http.StatusOK, toMemberProjectDTO(p), "项目已创建")
}

// APIMemberProjectGet mirrors MemberProjectEdit: returns a single project.
func (h *Handler) APIMemberProjectGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := h.st.GetProject(r.Context(), id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "项目不存在")
		return
	}
	apiOK(w, http.StatusOK, toMemberProjectDTO(p))
}

// APIMemberProjectUpdate mirrors MemberProjectUpdate.
func (h *Handler) APIMemberProjectUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in memberProjectInput
	if !decodeJSON(w, r, &in) {
		return
	}
	p := memberProjectFromInput(in)
	p.ID = id
	ctx := r.Context()
	p0, _ := h.st.GetProject(ctx, id) // capture before-state for audit
	if err := h.st.UpdateProject(ctx, p); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "保存失败："+err.Error())
		return
	}
	// Re-fetch for accurate after_state (includes ImageURL and DB-assigned fields).
	if saved, err := h.st.GetProject(ctx, id); err == nil {
		h.logAudit(ctx, h.currentUser(r), "update", "project", id, saved.NameZH, marshalJSON(p0), marshalJSON(saved))
		apiOKFlash(w, http.StatusOK, toMemberProjectDTO(saved), "已保存")
		return
	}
	h.logAudit(ctx, h.currentUser(r), "update", "project", id, p.NameZH, marshalJSON(p0), marshalJSON(p))
	apiOKFlash(w, http.StatusOK, toMemberProjectDTO(p), "已保存")
}

// APIMemberProjectDelete mirrors MemberProjectDelete.
func (h *Handler) APIMemberProjectDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	proj, _ := h.st.GetProject(ctx, id)
	// Delete DB record first; only clean up file on success.
	if err := h.st.DeleteProject(ctx, id); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "删除失败："+err.Error())
		return
	}
	if proj != nil {
		if proj.ImageURL != "" {
			removeUploadByBaseName("projects", "project-"+id)
		}
		h.logAudit(ctx, h.currentUser(r), "delete", "project", id, proj.NameZH, marshalJSON(proj), "")
	}
	apiOK(w, http.StatusOK, nil)
}

// APIMemberProjectUploadImage mirrors MemberProjectUploadImage (multipart).
func (h *Handler) APIMemberProjectUploadImage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	r.Body = http.MaxBytesReader(w, r.Body, MemberAdminImageOpts.MaxBytes)
	if err := r.ParseMultipartForm(MemberAdminImageOpts.MaxBytes); err != nil {
		apiErr(w, http.StatusRequestEntityTooLarge, "too_large", "文件过大（最大5MB）")
		return
	}
	if !h.verifyAPICSRF(r) {
		apiCSRFFailed(w)
		return
	}

	if _, err := h.st.GetProject(r.Context(), id); err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "项目不存在")
		return
	}

	file, _, err := r.FormFile("image_file")
	if err != nil {
		apiErr(w, http.StatusBadRequest, "validation", "未选择文件")
		return
	}
	defer file.Close()

	localURL, err := saveUploadedImage(file, "projects", "project-"+id, MemberAdminImageOpts)
	if err != nil {
		apiErr(w, http.StatusBadRequest, "validation", err.Error())
		return
	}

	if err := h.st.UpdateProjectImage(r.Context(), id, localURL); err != nil {
		// DB write failed; remove the file to avoid orphan.
		removeUploadByBaseName("projects", "project-"+id)
		apiErr(w, http.StatusConflict, "conflict", "保存图片失败")
		return
	}
	apiOKFlash(w, http.StatusOK, map[string]any{"imageUrl": localURL}, "图片已上传")
}

// ── 友情链接 ───────────────────────────────────────────────────────────────────

// APIMemberLinks mirrors MemberLinks: lists all friend links.
func (h *Handler) APIMemberLinks(w http.ResponseWriter, r *http.Request) {
	links, _ := h.st.ListFriendLinks(r.Context())
	apiOK(w, http.StatusOK, toMemberLinkDTOs(links))
}

// APIMemberLinkCreate mirrors MemberLinkCreate.
func (h *Handler) APIMemberLinkCreate(w http.ResponseWriter, r *http.Request) {
	var in memberLinkInput
	if !decodeJSON(w, r, &in) {
		return
	}
	name := strings.TrimSpace(in.Name)
	url := strings.TrimSpace(in.URL)
	icon := strings.TrimSpace(in.Icon)
	sortOrder := in.SortOrder
	ctx := r.Context()

	if name == "" || url == "" {
		apiErr(w, http.StatusBadRequest, "validation", "名称和链接地址不能为空")
		return
	}
	if !isAllowedAbsoluteURL(url) {
		apiErr(w, http.StatusBadRequest, "validation", "链接地址必须是安全协议地址，或本机调试地址")
		return
	}
	if err := h.st.CreateFriendLink(ctx, name, url, icon, sortOrder); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "创建失败："+err.Error())
		return
	}
	// Best-effort audit: fetch newly created link by name for ID.
	var created *store.FriendLink
	if links, _ := h.st.ListFriendLinks(ctx); len(links) > 0 {
		for _, l := range links {
			if l.Name == name && l.URL == url {
				created = l
				h.logAudit(ctx, h.currentUser(r), "create", "link", l.ID, l.Name, "", marshalJSON(l))
				break
			}
		}
	}
	apiOKFlash(w, http.StatusOK, toMemberLinkDTO(created), "链接已创建")
}

// APIMemberLinkGet mirrors MemberLinkEdit: returns a single friend link.
func (h *Handler) APIMemberLinkGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	l, err := h.st.GetFriendLink(r.Context(), id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "链接不存在")
		return
	}
	apiOK(w, http.StatusOK, toMemberLinkDTO(l))
}

// APIMemberLinkUpdate mirrors MemberLinkUpdate.
func (h *Handler) APIMemberLinkUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in memberLinkInput
	if !decodeJSON(w, r, &in) {
		return
	}
	name := strings.TrimSpace(in.Name)
	url := strings.TrimSpace(in.URL)
	icon := strings.TrimSpace(in.Icon)
	sortOrder := in.SortOrder
	ctx := r.Context()
	link0, _ := h.st.GetFriendLink(ctx, id) // capture before-state for audit

	if name == "" || url == "" {
		apiErr(w, http.StatusBadRequest, "validation", "名称和链接地址不能为空")
		return
	}
	if !isAllowedAbsoluteURL(url) {
		apiErr(w, http.StatusBadRequest, "validation", "链接地址必须是安全协议地址，或本机调试地址")
		return
	}
	if err := h.st.UpdateFriendLink(ctx, id, name, url, icon, sortOrder); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "保存失败："+err.Error())
		return
	}
	updated, _ := h.st.GetFriendLink(ctx, id)
	if updated != nil {
		h.logAudit(ctx, h.currentUser(r), "update", "link", id, updated.Name, marshalJSON(link0), marshalJSON(updated))
	}
	apiOKFlash(w, http.StatusOK, toMemberLinkDTO(updated), "已保存")
}

// APIMemberLinkDelete mirrors MemberLinkDelete.
func (h *Handler) APIMemberLinkDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	existing, _ := h.st.GetFriendLink(ctx, id)
	if err := h.st.DeleteFriendLink(ctx, id); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "删除失败："+err.Error())
		return
	}
	if existing != nil {
		h.logAudit(ctx, h.currentUser(r), "delete", "link", id, existing.Name, marshalJSON(existing), "")
	}
	apiOK(w, http.StatusOK, nil)
}

// APIMemberLinkUploadIcon mirrors MemberLinkUploadIcon (multipart).
func (h *Handler) APIMemberLinkUploadIcon(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	r.Body = http.MaxBytesReader(w, r.Body, MemberAdminImageOpts.MaxBytes)
	if err := r.ParseMultipartForm(MemberAdminImageOpts.MaxBytes); err != nil {
		apiErr(w, http.StatusRequestEntityTooLarge, "too_large", "文件过大（最大5MB）")
		return
	}
	if !h.verifyAPICSRF(r) {
		apiCSRFFailed(w)
		return
	}

	link, err := h.st.GetFriendLink(r.Context(), id)
	if err != nil || link == nil {
		apiErr(w, http.StatusNotFound, "not_found", "友情链接不存在")
		return
	}

	file, _, err := r.FormFile("icon_file")
	if err != nil {
		apiErr(w, http.StatusBadRequest, "validation", "未选择文件")
		return
	}
	defer file.Close()

	localURL, err := saveUploadedImage(file, "links", id, MemberAdminImageOpts)
	if err != nil {
		apiErr(w, http.StatusBadRequest, "validation", err.Error())
		return
	}
	if err := h.st.UpdateFriendLinkIcon(r.Context(), id, localURL); err != nil {
		removeUploadByBaseName("links", id)
		apiErr(w, http.StatusConflict, "conflict", "保存图标失败")
		return
	}
	apiOKFlash(w, http.StatusOK, map[string]any{"iconUrl": localURL}, "图标已上传")
}

// ── 用户管理 ───────────────────────────────────────────────────────────────────

// APIMemberUsers mirrors MemberUsers: lists users, EXCLUDING admin accounts.
func (h *Handler) APIMemberUsers(w http.ResponseWriter, r *http.Request) {
	allUsers, _ := h.st.ListUsers(r.Context())
	// Members must not see admin accounts.
	var users []*store.User
	for _, u := range allUsers {
		if !u.IsAdmin() {
			users = append(users, u)
		}
	}
	apiOK(w, http.StatusOK, toUserDTOs(users))
}

// APIMemberUserDetail mirrors MemberUserDetail.
func (h *Handler) APIMemberUserDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	u, err := h.st.GetUserByID(ctx, id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	// Members cannot view admin account details.
	if u.IsAdmin() {
		apiErr(w, http.StatusForbidden, "forbidden", "不能查看管理员账户详情")
		return
	}
	userGroups, _ := h.st.GetUserGroups(ctx, id)
	apiOK(w, http.StatusOK, map[string]any{
		"user":   toUserDTO(u),
		"groups": toMemberUserGroupDTOs(userGroups),
	})
}

// APIMemberUserVerifyEmail mirrors MemberUserVerifyEmail.
func (h *Handler) APIMemberUserVerifyEmail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	targetUser, err := h.st.GetUserByID(ctx, id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	if targetUser.IsAdmin() {
		apiErr(w, http.StatusForbidden, "forbidden", "不能修改管理员账户")
		return
	}
	if err := h.st.SetEmailVerified(ctx, id, true); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "操作失败")
		return
	}
	h.logAudit(ctx, h.currentUser(r), "update", "user", id, targetUser.Email,
		marshalJSON(map[string]bool{"email_verified": targetUser.EmailVerified}),
		marshalJSON(map[string]bool{"email_verified": true}))
	apiOKFlash(w, http.StatusOK, map[string]any{"emailVerified": true}, "邮箱已验证")
}

// APIMemberUserToggleStatus mirrors MemberUserToggleStatus.
func (h *Handler) APIMemberUserToggleStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	targetUser, err := h.st.GetUserByID(ctx, id)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	if h.isSystemAdminUser(targetUser) {
		apiErr(w, http.StatusForbidden, "forbidden", "不能修改系统管理员账户")
		return
	}
	if targetUser.IsAdmin() {
		apiErr(w, http.StatusForbidden, "forbidden", "不能修改管理员账户")
		return
	}
	newActive := !targetUser.Active
	if err := h.st.SetUserActive(ctx, id, newActive); err != nil {
		apiErr(w, http.StatusConflict, "conflict", "操作失败")
		return
	}
	h.logAudit(ctx, h.currentUser(r), "update", "user", id, targetUser.Email,
		marshalJSON(map[string]bool{"active": targetUser.Active}),
		marshalJSON(map[string]bool{"active": newActive}))
	if newActive {
		apiOKFlash(w, http.StatusOK, map[string]any{"active": true}, "账户已启用")
		return
	}
	apiOKFlash(w, http.StatusOK, map[string]any{"active": false}, "账户已停用")
}
