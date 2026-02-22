package server

import (
	"net/http"
	"strings"
)

func (h *Handler) Home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		h.renderError(w, r, http.StatusNotFound, "页面不存在", r.URL.Path)
		return
	}
	projects, _ := h.st.ListProjects(r.Context())
	d := h.pageData(r, "MTF - Team TransMTF")
	d.Data = projects
	h.render(w, "home", d)
}

func (h *Handler) LoginPage(w http.ResponseWriter, r *http.Request) {
	if h.currentUser(r) != nil {
		http.Redirect(w, r, safeNextPath(r.URL.Query().Get("next"), "/profile"), http.StatusFound)
		return
	}
	providers, _ := h.st.ListEnabledOIDCProviders(r.Context())
	d := h.pageData(r, "登录")
	d.Data = map[string]any{
		"Next":      safeNextPath(r.URL.Query().Get("next"), ""),
		"Providers": providers,
	}
	h.render(w, "login", d)
}

func (h *Handler) LoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	pass := r.FormValue("password")
	next := safeNextPath(r.FormValue("next"), "/profile")

	ctx := r.Context()
	u, err := h.st.GetUserByEmail(ctx, email)
	if err != nil || !h.st.VerifyPassword(u, pass) || !u.Active {
		providers, _ := h.st.ListEnabledOIDCProviders(ctx)
		d := h.pageData(r, "登录")
		d.Flash = "邮箱或密码错误"
		d.IsError = true
		d.Data = map[string]any{"Next": next, "Providers": providers}
		h.render(w, "login", d)
		return
	}
	if h.startSecondFactor(w, r, u, next) {
		return
	}

	sid, err := h.st.CreateSession(ctx, u.ID)
	if err != nil {
		h.renderError(w, r, http.StatusInternalServerError, "服务器错误", err.Error())
		return
	}
	h.setSessionCookie(w, sid)
	http.Redirect(w, r, next, http.StatusFound)
}

func (h *Handler) RegisterPage(w http.ResponseWriter, r *http.Request) {
	d := h.pageData(r, "注册")
	h.render(w, "register", d)
}

func (h *Handler) RegisterPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	pass := r.FormValue("password")
	confirm := r.FormValue("confirm")
	name := strings.TrimSpace(r.FormValue("display_name"))

	fail := func(msg string) {
		d := h.pageData(r, "注册")
		d.Flash = msg
		d.IsError = true
		h.render(w, "register", d)
	}

	if email == "" || pass == "" || name == "" {
		fail("请填写所有字段")
		return
	}
	if len(pass) < 8 {
		fail("密码至少 8 位")
		return
	}
	if pass != confirm {
		fail("两次密码不一致")
		return
	}

	ctx := r.Context()
	u, err := h.st.CreateUser(ctx, email, pass, name, "user")
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			fail("该邮箱已注册")
		} else {
			fail("注册失败: " + err.Error())
		}
		return
	}

	sid, err := h.st.CreateSession(ctx, u.ID)
	if err == nil {
		h.setSessionCookie(w, sid)
	}
	http.Redirect(w, r, "/profile", http.StatusFound)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	sid := h.sessionFromRequest(r)
	if sid != "" {
		_ = h.st.DeleteSession(r.Context(), sid)
	}
	h.clearSessionCookie(w)
	h.clear2FAChallengeCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handler) Profile(w http.ResponseWriter, r *http.Request) {
	d := h.pageData(r, "个人资料")
	if u := h.currentUser(r); u != nil && u.TOTPPendingSecret != "" {
		d.Data = map[string]any{
			"PendingSecret": u.TOTPPendingSecret,
			"PendingURI":    buildTOTPUri(orDefault(h.st.GetSetting(r.Context(), "site_name"), "Team TransMTF"), u.Email, u.TOTPPendingSecret),
		}
	}
	h.render(w, "profile", d)
}

func (h *Handler) ProfilePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.csrfFailed(w, r)
		return
	}

	u := h.currentUser(r)
	ctx := r.Context()
	name := strings.TrimSpace(r.FormValue("display_name"))
	avatar := strings.TrimSpace(r.FormValue("avatar_url"))
	newPass := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	fail := func(msg string) {
		d := h.pageData(r, "个人资料")
		d.Flash = msg
		d.IsError = true
		if u != nil && u.TOTPPendingSecret != "" {
			d.Data = map[string]any{
				"PendingSecret": u.TOTPPendingSecret,
				"PendingURI":    buildTOTPUri(orDefault(h.st.GetSetting(r.Context(), "site_name"), "Team TransMTF"), u.Email, u.TOTPPendingSecret),
			}
		}
		h.render(w, "profile", d)
	}

	if name == "" {
		fail("显示名称不能为空")
		return
	}
	if err := h.st.UpdateUser(ctx, u.ID, name, u.Role, u.Active); err != nil {
		fail("保存失败: " + err.Error())
		return
	}
	if avatar != "" {
		_ = h.st.UpdateUserAvatar(ctx, u.ID, avatar)
	}

	if newPass != "" {
		if len(newPass) < 8 {
			fail("新密码至少 8 位")
			return
		}
		if newPass != confirm {
			fail("两次密码不一致")
			return
		}
		if err := h.st.UpdatePassword(ctx, u.ID, newPass); err != nil {
			fail("密码修改失败")
			return
		}
	}

	d := h.pageData(r, "个人资料")
	d.Flash = "保存成功"
	if u != nil && u.TOTPPendingSecret != "" {
		d.Data = map[string]any{
			"PendingSecret": u.TOTPPendingSecret,
			"PendingURI":    buildTOTPUri(orDefault(h.st.GetSetting(r.Context(), "site_name"), "Team TransMTF"), u.Email, u.TOTPPendingSecret),
		}
	}
	h.render(w, "profile", d)
}

func (h *Handler) TOSPage(w http.ResponseWriter, r *http.Request) {
	d := h.pageData(r, "服务条款")
	d.Data = h.st.GetSetting(r.Context(), "tos_content")
	h.render(w, "tos", d)
}

func (h *Handler) PrivacyPage(w http.ResponseWriter, r *http.Request) {
	d := h.pageData(r, "隐私政策")
	d.Data = h.st.GetSetting(r.Context(), "privacy_content")
	h.render(w, "privacy", d)
}
