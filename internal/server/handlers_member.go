package server

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"transmtf.com/oidc/internal/store"
)

// 项目管理

func (h *Handler) MemberProjects(w http.ResponseWriter, r *http.Request) {
	projects, _ := h.st.ListProjects(r.Context())
	d := h.pageData(r, "项目管理")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = projects
	h.render(w, "member_projects", d)
}

func (h *Handler) MemberProjectCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	p := projectFromForm(r)
	ctx := r.Context()
	d := h.pageData(r, "项目管理")
	if err := h.st.CreateProject(ctx, p); err != nil {
		projects, _ := h.st.ListProjects(ctx)
		d.Data = projects
		d.Flash = "创建失败：" + err.Error()
		d.IsError = true
		h.render(w, "member_projects", d)
		return
	}

	http.Redirect(w, r, "/member/projects?flash=项目已创建", http.StatusFound)
}

func (h *Handler) MemberProjectEdit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := h.st.GetProject(r.Context(), id)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, "项目不存在", id)
		return
	}
	d := h.pageData(r, "编辑项目")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = p
	h.render(w, "member_project_edit", d)
}

func (h *Handler) MemberProjectUpdate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	id := r.PathValue("id")
	p := projectFromForm(r)
	p.ID = id
	ctx := r.Context()
	d := h.pageData(r, "编辑项目")
	if err := h.st.UpdateProject(ctx, p); err != nil {
		d.Data = p
		d.Flash = "保存失败：" + err.Error()
		d.IsError = true
		h.render(w, "member_project_edit", d)
		return
	}
	http.Redirect(w, r, "/member/projects/"+id+"/edit?flash=已保存", http.StatusFound)
}

func (h *Handler) MemberProjectDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	id := r.PathValue("id")
	_ = h.st.DeleteProject(r.Context(), id)
	http.Redirect(w, r, "/member/projects", http.StatusFound)
}

func (h *Handler) MemberProjectUploadImage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	redirectEdit := "/member/projects/" + id + "/edit"

	r.Body = http.MaxBytesReader(w, r.Body, 1*1024*1024)
	if err := r.ParseMultipartForm(1 * 1024 * 1024); err != nil {
		http.Redirect(w, r, redirectEdit+"?flash=文件过大（最大1MB）", http.StatusFound)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	if _, err := h.st.GetProject(r.Context(), id); err != nil {
		h.renderError(w, r, http.StatusNotFound, "项目不存在", id)
		return
	}

	file, _, err := r.FormFile("image_file")
	if err != nil {
		http.Redirect(w, r, redirectEdit+"?flash=未选择文件", http.StatusFound)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		http.Redirect(w, r, redirectEdit+"?flash=读取文件失败", http.StatusFound)
		return
	}
	if len(data) == 0 {
		http.Redirect(w, r, redirectEdit+"?flash=文件为空", http.StatusFound)
		return
	}

	mimeType := http.DetectContentType(data)
	ext, ok := projectImageExt(mimeType)
	if !ok {
		http.Redirect(w, r, redirectEdit+"?flash=仅支持PNG/JPEG图片", http.StatusFound)
		return
	}

	if err := os.MkdirAll("uploads", 0o755); err != nil {
		http.Redirect(w, r, redirectEdit+"?flash=服务器错误", http.StatusFound)
		return
	}

	// Remove old image files for this project (either extension).
	for _, oldExt := range []string{".png", ".jpg"} {
		_ = os.Remove(filepath.Join("uploads", "project-"+id+oldExt))
	}

	fileName := "project-" + id + ext
	if err := os.WriteFile(filepath.Join("uploads", fileName), data, 0o644); err != nil {
		http.Redirect(w, r, redirectEdit+"?flash=保存图片失败", http.StatusFound)
		return
	}

	_ = h.st.UpdateProjectImage(r.Context(), id, "/uploads/"+fileName)
	http.Redirect(w, r, redirectEdit+"?flash=图片已上传", http.StatusFound)
}

func projectImageExt(mimeType string) (string, bool) {
	switch mimeType {
	case "image/png":
		return ".png", true
	case "image/jpeg":
		return ".jpg", true
	default:
		return "", false
	}
}

func projectFromForm(r *http.Request) *store.Project {
	sortOrder, _ := strconv.Atoi(r.FormValue("sort_order"))
	return &store.Project{
		Slug:      strings.TrimSpace(r.FormValue("slug")),
		NameZH:    strings.TrimSpace(r.FormValue("name_zh")),
		NameEN:    strings.TrimSpace(r.FormValue("name_en")),
		DescZH:    r.FormValue("desc_zh"),
		DescEN:    r.FormValue("desc_en"),
		Status:    r.FormValue("status"),
		URL:       strings.TrimSpace(r.FormValue("url")),
		Tags:      r.FormValue("tags"),
		Featured:  r.FormValue("featured") == "1",
		SortOrder: sortOrder,
	}
}

// 友情链接

func (h *Handler) MemberLinks(w http.ResponseWriter, r *http.Request) {
	links, _ := h.st.ListFriendLinks(r.Context())
	d := h.pageData(r, "友情链接管理")
	if flash := r.URL.Query().Get("flash"); flash != "" {
		d.Flash = flash
	}
	d.Data = links
	h.render(w, "member_links", d)
}

func (h *Handler) MemberLinkCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	url := strings.TrimSpace(r.FormValue("url"))
	icon := strings.TrimSpace(r.FormValue("icon"))
	sortOrder, _ := strconv.Atoi(r.FormValue("sort_order"))
	ctx := r.Context()

	renderErr := func(msg string) {
		links, _ := h.st.ListFriendLinks(ctx)
		d := h.pageData(r, "友情链接管理")
		d.Data = links
		d.Flash = msg
		d.IsError = true
		h.render(w, "member_links", d)
	}

	if name == "" || url == "" {
		renderErr("名称和链接地址不能为空")
		return
	}
	if !isAllowedAbsoluteURL(url) {
		renderErr("链接地址必须是安全协议地址，或本机调试地址")
		return
	}
	if err := h.st.CreateFriendLink(ctx, name, url, icon, sortOrder); err != nil {
		renderErr("创建失败：" + err.Error())
		return
	}
	http.Redirect(w, r, "/member/links?flash=链接已创建", http.StatusFound)
}

func (h *Handler) MemberLinkEdit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	l, err := h.st.GetFriendLink(r.Context(), id)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, "链接不存在", id)
		return
	}
	d := h.pageData(r, "编辑友情链接")
	d.Data = l
	h.render(w, "member_link_edit", d)
}

func (h *Handler) MemberLinkUpdate(w http.ResponseWriter, r *http.Request) {
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
	url := strings.TrimSpace(r.FormValue("url"))
	icon := strings.TrimSpace(r.FormValue("icon"))
	sortOrder, _ := strconv.Atoi(r.FormValue("sort_order"))
	ctx := r.Context()

	renderErr := func(msg string) {
		l, _ := h.st.GetFriendLink(ctx, id)
		d := h.pageData(r, "编辑友情链接")
		d.Data = l
		d.Flash = msg
		d.IsError = true
		h.render(w, "member_link_edit", d)
	}

	if name == "" || url == "" {
		renderErr("名称和链接地址不能为空")
		return
	}
	if !isAllowedAbsoluteURL(url) {
		renderErr("链接地址必须是安全协议地址，或本机调试地址")
		return
	}
	if err := h.st.UpdateFriendLink(ctx, id, name, url, icon, sortOrder); err != nil {
		renderErr("保存失败：" + err.Error())
		return
	}
	http.Redirect(w, r, "/member/links?flash=已保存", http.StatusFound)
}

func (h *Handler) MemberLinkDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求参数错误", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}
	_ = h.st.DeleteFriendLink(r.Context(), r.PathValue("id"))
	http.Redirect(w, r, "/member/links", http.StatusFound)
}
