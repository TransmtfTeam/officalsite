package server

import (
	"net/http"
	"strconv"
	"strings"

	"transmtf.com/oidc/internal/store"
)

func (h *Handler) MemberProjects(w http.ResponseWriter, r *http.Request) {
	projects, _ := h.st.ListProjects(r.Context())
	d := h.pageData(r, "项目管理")
	d.Data = projects
	h.render(w, "member_projects", d)
}

func (h *Handler) MemberProjectCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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
		d.Flash = "创建失败: " + err.Error()
		d.IsError = true
		h.render(w, "member_projects", d)
		return
	}

	projects, _ := h.st.ListProjects(ctx)
	d.Data = projects
	d.Flash = "项目已创建"
	h.render(w, "member_projects", d)
}

func (h *Handler) MemberProjectEdit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := h.st.GetProject(r.Context(), id)
	if err != nil {
		h.renderError(w, r, http.StatusNotFound, "项目不存在", id)
		return
	}
	d := h.pageData(r, "编辑项目")
	d.Data = p
	h.render(w, "member_project_edit", d)
}

func (h *Handler) MemberProjectUpdate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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
		d.Flash = "保存失败: " + err.Error()
		d.IsError = true
		h.render(w, "member_project_edit", d)
		return
	}
	d.Data = p
	d.Flash = "保存成功"
	h.render(w, "member_project_edit", d)
}

func (h *Handler) MemberProjectDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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
