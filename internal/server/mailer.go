package server

import (
	"context"
	"fmt"
	"log"
	"strings"

	"transmtf.com/oidc/internal/email"
)

// mailer 根据当前站点设置构建邮件发送器。
func (h *Handler) mailer(ctx context.Context) email.Sender {
	return email.New(h.st.GetAllSettings(ctx))
}

// defaultWelcomeHTML 是欢迎邮件的默认富文本模板。
// 占位变量：{{SiteName}}、{{SiteIconHTML}}、{{Name}}、{{ProfileURL}}
const defaultWelcomeHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:24px;background:#f5f7fb;font-family:Segoe UI,Roboto,sans-serif;color:#1f2937">
  <div style="max-width:560px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:28px">
    <div style="text-align:center;margin-bottom:18px">
      {{SiteIconHTML}}
      <h1 style="margin:0;font-size:22px">{{SiteName}}</h1>
    </div>
    <h2 style="margin:0 0 10px;font-size:20px">欢迎加入 {{SiteName}}</h2>
    <p style="margin:0 0 16px;line-height:1.7">{{Name}}，你好，你的账号已可使用。</p>
    <p style="margin:0 0 22px;line-height:1.7">你可以点击下方按钮完善个人资料。</p>
    <a href="{{ProfileURL}}" style="display:inline-block;background:#2563eb;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none">打开个人资料</a>
    <p style="margin:24px 0 0;font-size:13px;color:#6b7280">{{SiteName}} 系统邮件，请勿回复。</p>
  </div>
</body>
</html>`

// defaultPasswordResetHTML 是密码重置通知邮件的默认富文本模板。
// 占位变量：{{SiteName}}、{{SiteIconHTML}}、{{Name}}、{{NewPassword}}、{{ProfileURL}}
const defaultPasswordResetHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:24px;background:#f5f7fb;font-family:Segoe UI,Roboto,sans-serif;color:#1f2937">
  <div style="max-width:560px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:28px">
    <div style="text-align:center;margin-bottom:18px">
      {{SiteIconHTML}}
      <h1 style="margin:0;font-size:22px">{{SiteName}}</h1>
    </div>
    <h2 style="margin:0 0 10px;font-size:20px">密码已被重置</h2>
    <p style="margin:0 0 16px;line-height:1.7">{{Name}}，你好，管理员已重置你的密码。</p>
    <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:12px 14px;margin-bottom:18px;text-align:center">
      <code style="font-size:18px;font-weight:700">{{NewPassword}}</code>
    </div>
    <p style="margin:0 0 20px;line-height:1.7">请立即登录并修改此密码。</p>
    <a href="{{ProfileURL}}" style="display:inline-block;background:#2563eb;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none">修改密码</a>
    <p style="margin:24px 0 0;font-size:13px;color:#6b7280">{{SiteName}} 系统邮件，请勿回复。</p>
  </div>
</body>
</html>`

// renderEmailTpl 在模板中替换简单的 {{Key}} 占位符。
func renderEmailTpl(tpl string, vars map[string]string) string {
	r := make([]string, 0, len(vars)*2)
	for k, v := range vars {
		r = append(r, "{{"+k+"}}", v)
	}
	return strings.NewReplacer(r...).Replace(tpl)
}

// siteIconImgHTML 返回站点图标的 <img> 标签；若没有图标则返回空字符串。
func siteIconImgHTML(issuer, iconURL, altText string) string {
	if iconURL == "" {
		return ""
	}
	// 使用统一接口，兼容数据地址与常规地址。
	src := issuer + "/api/site-icon"
	return `<img src="` + src + `" alt="` + altText + `" style="height:48px;width:48px;border-radius:8px;margin-bottom:12px;display:block;margin-left:auto;margin-right:auto">`
}

// defaultVerifyHTML 是邮箱验证邮件的默认富文本模板。
// 占位变量：{{SiteName}}、{{SiteIconHTML}}、{{Name}}、{{VerifyURL}}
const defaultVerifyHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:24px;background:#f5f7fb;font-family:Segoe UI,Roboto,sans-serif;color:#1f2937">
  <div style="max-width:560px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:28px">
    <div style="text-align:center;margin-bottom:18px">
      {{SiteIconHTML}}
      <h1 style="margin:0;font-size:22px">{{SiteName}}</h1>
    </div>
    <h2 style="margin:0 0 10px;font-size:20px">验证您的邮箱</h2>
    <p style="margin:0 0 18px;line-height:1.7">{{Name}}，你好，点击下方按钮验证邮箱。链接将在 24 小时后过期。</p>
    <a href="{{VerifyURL}}" style="display:inline-block;background:#2563eb;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none">验证邮箱</a>
    <p style="margin:20px 0 0;font-size:13px;color:#6b7280">如果按钮无法使用，请打开以下地址：</p>
    <p style="margin:8px 0 0;font-size:13px;word-break:break-all;color:#374151">{{VerifyURL}}</p>
    <p style="margin:24px 0 0;font-size:13px;color:#6b7280">{{SiteName}} 系统邮件，请勿回复。</p>
  </div>
</body>
</html>`

// defaultForgotPasswordHTML 是找回密码邮件的默认富文本模板。
// 占位变量：{{SiteName}}、{{SiteIconHTML}}、{{Name}}、{{ResetURL}}
const defaultForgotPasswordHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:24px;background:#f5f7fb;font-family:Segoe UI,Roboto,sans-serif;color:#1f2937">
  <div style="max-width:560px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:28px">
    <div style="text-align:center;margin-bottom:18px">
      {{SiteIconHTML}}
      <h1 style="margin:0;font-size:22px">{{SiteName}}</h1>
    </div>
    <h2 style="margin:0 0 10px;font-size:20px">重置您的密码</h2>
    <p style="margin:0 0 18px;line-height:1.7">{{Name}}，你好，点击下方按钮重置密码。链接将在 30 分钟后过期。</p>
    <a href="{{ResetURL}}" style="display:inline-block;background:#2563eb;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none">重置密码</a>
    <p style="margin:20px 0 0;font-size:13px;color:#6b7280">如果按钮无法使用，请打开以下地址：</p>
    <p style="margin:8px 0 0;font-size:13px;word-break:break-all;color:#374151">{{ResetURL}}</p>
    <p style="margin:24px 0 0;font-size:13px;color:#6b7280">{{SiteName}} 系统邮件，请勿回复。</p>
  </div>
</body>
</html>`

// sendVerificationEmail 发送邮箱验证链接。
func (h *Handler) sendVerificationEmail(ctx context.Context, toEmail, name, token string) {
	siteName := orDefault(h.st.GetSetting(ctx, "site_name"), "团队站点")
	iconHTML := siteIconImgHTML(h.cfg.Issuer, h.st.GetSetting(ctx, "site_icon_url"), siteName)
	verifyURL := h.cfg.Issuer + "/verify-email?token=" + token

	vars := map[string]string{
		"SiteName":     siteName,
		"SiteIconHTML": iconHTML,
		"Name":         name,
		"VerifyURL":    verifyURL,
	}

	subject := "[" + siteName + "] 验证您的邮箱"
	textBody := name + "，你好：\n\n请通过下方链接验证邮箱（24 小时内有效）：\n" + verifyURL + "\n\n" + siteName
	htmlBody := renderEmailTpl(defaultVerifyHTML, vars)

	if err := h.mailer(ctx).SendHTML(toEmail, subject, textBody, htmlBody); err != nil {
		log.Printf("email: verify to %s: %v", toEmail, err)
	}
}

func (h *Handler) sendForgotPasswordEmail(ctx context.Context, toEmail, name, token string) {
	siteName := orDefault(h.st.GetSetting(ctx, "site_name"), "团队站点")
	iconHTML := siteIconImgHTML(h.cfg.Issuer, h.st.GetSetting(ctx, "site_icon_url"), siteName)
	resetURL := h.cfg.Issuer + "/reset-password?token=" + token

	vars := map[string]string{
		"SiteName":     siteName,
		"SiteIconHTML": iconHTML,
		"Name":         name,
		"ResetURL":     resetURL,
	}

	subject := "[" + siteName + "] 重置密码"
	textBody := name + "，你好：\n\n请通过下方链接重置密码（30 分钟内有效）：\n" + resetURL + "\n\n" + siteName
	htmlBody := renderEmailTpl(defaultForgotPasswordHTML, vars)

	if err := h.mailer(ctx).SendHTML(toEmail, subject, textBody, htmlBody); err != nil {
		log.Printf("email: forgot password to %s: %v", toEmail, err)
	}
}

// sendWelcomeEmail 发送注册欢迎邮件。
func (h *Handler) sendWelcomeEmail(ctx context.Context, toEmail, name string) {
	siteName := orDefault(h.st.GetSetting(ctx, "site_name"), "团队站点")
	profileURL := h.cfg.Issuer + "/profile"
	iconHTML := siteIconImgHTML(h.cfg.Issuer, h.st.GetSetting(ctx, "site_icon_url"), siteName)

	vars := map[string]string{
		"SiteName":     siteName,
		"SiteIconHTML": iconHTML,
		"Name":         name,
		"ProfileURL":   profileURL,
	}

	subject := "欢迎加入 " + siteName
	textBody := fmt.Sprintf(
		"%s，欢迎加入 %s。\n\n请通过以下地址完善个人资料：\n%s\n\n%s",
		name, siteName, profileURL, siteName,
	)

	htmlTpl := h.st.GetSetting(ctx, "email_tpl_welcome")
	if htmlTpl == "" {
		htmlTpl = defaultWelcomeHTML
	}
	htmlBody := renderEmailTpl(htmlTpl, vars)

	if err := h.mailer(ctx).SendHTML(toEmail, subject, textBody, htmlBody); err != nil {
		log.Printf("email: welcome to %s: %v", toEmail, err)
	}
}

// sendPasswordResetEmail 通知用户管理员已重置其密码。
func (h *Handler) sendPasswordResetEmail(ctx context.Context, toEmail, name, newPass string) {
	siteName := orDefault(h.st.GetSetting(ctx, "site_name"), "团队站点")
	profileURL := h.cfg.Issuer + "/profile"
	iconHTML := siteIconImgHTML(h.cfg.Issuer, h.st.GetSetting(ctx, "site_icon_url"), siteName)

	vars := map[string]string{
		"SiteName":     siteName,
		"SiteIconHTML": iconHTML,
		"Name":         name,
		"NewPassword":  newPass,
		"ProfileURL":   profileURL,
	}

	subject := fmt.Sprintf("[%s] 密码重置", siteName)
	textBody := fmt.Sprintf(
		"%s，您好：\n\n管理员已重置你的账户密码。\n新密码：%s\n\n请立即登录并修改密码：\n%s\n\n%s",
		name, newPass, profileURL, siteName,
	)

	htmlTpl := h.st.GetSetting(ctx, "email_tpl_password_reset")
	if htmlTpl == "" {
		htmlTpl = defaultPasswordResetHTML
	}
	htmlBody := renderEmailTpl(htmlTpl, vars)

	if err := h.mailer(ctx).SendHTML(toEmail, subject, textBody, htmlBody); err != nil {
		log.Printf("email: password reset to %s: %v", toEmail, err)
	}
}
