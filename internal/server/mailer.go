package server

import (
	"context"
	"fmt"
	"log"
	"strings"

	"transmtf.com/oidc/internal/email"
)

// mailer builds an email.Sender from the current site settings.
func (h *Handler) mailer(ctx context.Context) email.Sender {
	return email.New(h.st.GetAllSettings(ctx))
}

// defaultWelcomeHTML is the styled HTML template for welcome emails.
// Placeholders: {{SiteName}}, {{SiteIconHTML}}, {{Name}}, {{ProfileURL}}
const defaultWelcomeHTML = `<!DOCTYPE html>
<html lang="zh">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f0f4f8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f4f8;padding:48px 16px">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08)">
  <tr>
    <td style="background:linear-gradient(135deg,#3b82f6 0%,#ec4899 100%);padding:32px 40px;text-align:center">
      {{SiteIconHTML}}
      <h1 style="color:#ffffff;margin:0;font-size:22px;font-weight:800;letter-spacing:-.5px">{{SiteName}}</h1>
    </td>
  </tr>
  <tr>
    <td style="padding:40px">
      <h2 style="color:#1e293b;margin:0 0 12px;font-size:20px;font-weight:700">欢迎加入 {{SiteName}}</h2>
      <p style="color:#475569;margin:0 0 8px;line-height:1.7;font-size:15px">你好，{{Name}}，</p>
      <p style="color:#475569;margin:0 0 28px;line-height:1.7;font-size:15px">
        账号已创建成功，现在可以登录并完善你的个人资料。
      </p>
      <a href="{{ProfileURL}}"
         style="display:inline-block;background:linear-gradient(135deg,#3b82f6,#ec4899);color:#ffffff;padding:13px 30px;border-radius:10px;text-decoration:none;font-weight:600;font-size:15px">
        查看个人资料
      </a>
    </td>
  </tr>
  <tr>
    <td style="padding:20px 40px 24px;border-top:1px solid #f1f5f9;text-align:center">
      <p style="color:#94a3b8;margin:0;font-size:13px">{{SiteName}} · 此邮件由系统自动发送，请勿回复</p>
    </td>
  </tr>
</table>
</td></tr>
</table>
</body>
</html>`

// defaultPasswordResetHTML is the styled HTML template for password reset emails.
// Placeholders: {{SiteName}}, {{SiteIconHTML}}, {{Name}}, {{NewPassword}}, {{ProfileURL}}
const defaultPasswordResetHTML = `<!DOCTYPE html>
<html lang="zh">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f0f4f8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f4f8;padding:48px 16px">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08)">
  <tr>
    <td style="background:linear-gradient(135deg,#3b82f6 0%,#ec4899 100%);padding:32px 40px;text-align:center">
      {{SiteIconHTML}}
      <h1 style="color:#ffffff;margin:0;font-size:22px;font-weight:800;letter-spacing:-.5px">{{SiteName}}</h1>
    </td>
  </tr>
  <tr>
    <td style="padding:40px">
      <h2 style="color:#1e293b;margin:0 0 12px;font-size:20px;font-weight:700">密码已被重置</h2>
      <p style="color:#475569;margin:0 0 8px;line-height:1.7;font-size:15px">你好，{{Name}}，</p>
      <p style="color:#475569;margin:0 0 20px;line-height:1.7;font-size:15px">
        管理员已重置了你的账号密码，新密码如下：
      </p>
      <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:16px 20px;margin-bottom:24px;text-align:center">
        <code style="font-size:18px;font-weight:700;color:#1e293b;letter-spacing:1px">{{NewPassword}}</code>
      </div>
      <p style="color:#475569;margin:0 0 28px;line-height:1.7;font-size:15px">
        请登录后立即前往个人资料页修改密码。
      </p>
      <a href="{{ProfileURL}}"
         style="display:inline-block;background:linear-gradient(135deg,#3b82f6,#ec4899);color:#ffffff;padding:13px 30px;border-radius:10px;text-decoration:none;font-weight:600;font-size:15px">
        修改密码
      </a>
    </td>
  </tr>
  <tr>
    <td style="padding:20px 40px 24px;border-top:1px solid #f1f5f9;text-align:center">
      <p style="color:#94a3b8;margin:0;font-size:13px">{{SiteName}} · 此邮件由系统自动发送，请勿回复</p>
    </td>
  </tr>
</table>
</td></tr>
</table>
</body>
</html>`

// renderEmailTpl replaces simple {{Key}} placeholders in a template string.
func renderEmailTpl(tpl string, vars map[string]string) string {
	r := make([]string, 0, len(vars)*2)
	for k, v := range vars {
		r = append(r, "{{"+k+"}}", v)
	}
	return strings.NewReplacer(r...).Replace(tpl)
}

// siteIconImgHTML returns an HTML <img> tag for the site icon, or an empty string.
func siteIconImgHTML(issuer, iconURL, altText string) string {
	if iconURL == "" {
		return ""
	}
	// Use the API endpoint which handles both data URLs and regular URLs.
	src := issuer + "/api/site-icon"
	return `<img src="` + src + `" alt="` + altText + `" style="height:48px;width:48px;border-radius:8px;margin-bottom:12px;display:block;margin-left:auto;margin-right:auto">`
}

// defaultVerifyHTML is the styled HTML template for email verification.
// Placeholders: {{SiteName}}, {{SiteIconHTML}}, {{Name}}, {{VerifyURL}}
const defaultVerifyHTML = `<!DOCTYPE html>
<html lang="zh">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f0f4f8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f4f8;padding:48px 16px">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08)">
  <tr>
    <td style="background:linear-gradient(135deg,#3b82f6 0%,#ec4899 100%);padding:32px 40px;text-align:center">
      {{SiteIconHTML}}
      <h1 style="color:#ffffff;margin:0;font-size:22px;font-weight:800;letter-spacing:-.5px">{{SiteName}}</h1>
    </td>
  </tr>
  <tr>
    <td style="padding:40px">
      <h2 style="color:#1e293b;margin:0 0 12px;font-size:20px;font-weight:700">验证您的邮箱</h2>
      <p style="color:#475569;margin:0 0 8px;line-height:1.7;font-size:15px">你好，{{Name}}，</p>
      <p style="color:#475569;margin:0 0 28px;line-height:1.7;font-size:15px">
        请点击下方按钮完成邮箱验证。链接有效期为 24 小时。
      </p>
      <a href="{{VerifyURL}}"
         style="display:inline-block;background:linear-gradient(135deg,#3b82f6,#ec4899);color:#ffffff;padding:13px 30px;border-radius:10px;text-decoration:none;font-weight:600;font-size:15px">
        验证邮箱
      </a>
      <p style="color:#94a3b8;margin:28px 0 0;line-height:1.7;font-size:13px">
        如果按钮无法点击，请复制以下链接到浏览器：<br>
        <span style="word-break:break-all;color:#475569">{{VerifyURL}}</span>
      </p>
    </td>
  </tr>
  <tr>
    <td style="padding:20px 40px 24px;border-top:1px solid #f1f5f9;text-align:center">
      <p style="color:#94a3b8;margin:0;font-size:13px">{{SiteName}} · 此邮件由系统自动发送，请勿回复</p>
    </td>
  </tr>
</table>
</td></tr>
</table>
</body>
</html>`

// defaultForgotPasswordHTML is the styled HTML template for password reset links.
// Placeholders: {{SiteName}}, {{SiteIconHTML}}, {{Name}}, {{ResetURL}}
const defaultForgotPasswordHTML = `<!DOCTYPE html>
<html lang="zh">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f0f4f8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f4f8;padding:48px 16px">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08)">
  <tr>
    <td style="background:linear-gradient(135deg,#3b82f6 0%,#ec4899 100%);padding:32px 40px;text-align:center">
      {{SiteIconHTML}}
      <h1 style="color:#ffffff;margin:0;font-size:22px;font-weight:800;letter-spacing:-.5px">{{SiteName}}</h1>
    </td>
  </tr>
  <tr>
    <td style="padding:40px">
      <h2 style="color:#1e293b;margin:0 0 12px;font-size:20px;font-weight:700">重置您的密码</h2>
      <p style="color:#475569;margin:0 0 8px;line-height:1.7;font-size:15px">你好，{{Name}}，</p>
      <p style="color:#475569;margin:0 0 28px;line-height:1.7;font-size:15px">
        请点击下方按钮重置密码。链接有效期为 30 分钟。
      </p>
      <a href="{{ResetURL}}"
         style="display:inline-block;background:linear-gradient(135deg,#3b82f6,#ec4899);color:#ffffff;padding:13px 30px;border-radius:10px;text-decoration:none;font-weight:600;font-size:15px">
        重置密码
      </a>
      <p style="color:#94a3b8;margin:28px 0 0;line-height:1.7;font-size:13px">
        如果按钮无法点击，请复制以下链接到浏览器：<br>
        <span style="word-break:break-all;color:#475569">{{ResetURL}}</span>
      </p>
    </td>
  </tr>
  <tr>
    <td style="padding:20px 40px 24px;border-top:1px solid #f1f5f9;text-align:center">
      <p style="color:#94a3b8;margin:0;font-size:13px">{{SiteName}} · 此邮件由系统自动发送，请勿回复</p>
    </td>
  </tr>
</table>
</td></tr>
</table>
</body>
</html>`

// sendVerificationEmail sends an email verification link.
func (h *Handler) sendVerificationEmail(ctx context.Context, toEmail, name, token string) {
	siteName := orDefault(h.st.GetSetting(ctx, "site_name"), "Team TransMTF")
	iconHTML := siteIconImgHTML(h.cfg.Issuer, h.st.GetSetting(ctx, "site_icon_url"), siteName)
	verifyURL := h.cfg.Issuer + "/verify-email?token=" + token

	vars := map[string]string{
		"SiteName":     siteName,
		"SiteIconHTML": iconHTML,
		"Name":         name,
		"VerifyURL":    verifyURL,
	}

	subject := "【" + siteName + "】请验证您的邮箱"
	textBody := "你好，" + name + "，\n\n请点击以下链接完成邮箱验证（24小时内有效）：\n" + verifyURL + "\n\n" + siteName + " 团队"
	htmlBody := renderEmailTpl(defaultVerifyHTML, vars)

	if err := h.mailer(ctx).SendHTML(toEmail, subject, textBody, htmlBody); err != nil {
		log.Printf("email: verify to %s: %v", toEmail, err)
	}
}

func (h *Handler) sendForgotPasswordEmail(ctx context.Context, toEmail, name, token string) {
	siteName := orDefault(h.st.GetSetting(ctx, "site_name"), "Team TransMTF")
	iconHTML := siteIconImgHTML(h.cfg.Issuer, h.st.GetSetting(ctx, "site_icon_url"), siteName)
	resetURL := h.cfg.Issuer + "/reset-password?token=" + token

	vars := map[string]string{
		"SiteName":     siteName,
		"SiteIconHTML": iconHTML,
		"Name":         name,
		"ResetURL":     resetURL,
	}

	subject := "【" + siteName + "】重置密码"
	textBody := "你好，" + name + "，\n\n请点击以下链接重置密码（30分钟内有效）：\n" + resetURL + "\n\n" + siteName + " 团队"
	htmlBody := renderEmailTpl(defaultForgotPasswordHTML, vars)

	if err := h.mailer(ctx).SendHTML(toEmail, subject, textBody, htmlBody); err != nil {
		log.Printf("email: forgot password to %s: %v", toEmail, err)
	}
}

// sendWelcomeEmail sends a registration welcome message.
func (h *Handler) sendWelcomeEmail(ctx context.Context, toEmail, name string) {
	siteName := orDefault(h.st.GetSetting(ctx, "site_name"), "Team TransMTF")
	profileURL := h.cfg.Issuer + "/profile"
	iconHTML := siteIconImgHTML(h.cfg.Issuer, h.st.GetSetting(ctx, "site_icon_url"), siteName)

	vars := map[string]string{
		"SiteName":    siteName,
		"SiteIconHTML": iconHTML,
		"Name":        name,
		"ProfileURL":  profileURL,
	}

	subject := "欢迎加入 " + siteName
	textBody := fmt.Sprintf(
		"你好，%s，\n\n欢迎加入 %s。\n\n前往个人资料完善信息：\n%s\n\n%s 团队",
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

// sendPasswordResetEmail notifies a user that their password was reset by an admin.
func (h *Handler) sendPasswordResetEmail(ctx context.Context, toEmail, name, newPass string) {
	siteName := orDefault(h.st.GetSetting(ctx, "site_name"), "Team TransMTF")
	profileURL := h.cfg.Issuer + "/profile"
	iconHTML := siteIconImgHTML(h.cfg.Issuer, h.st.GetSetting(ctx, "site_icon_url"), siteName)

	vars := map[string]string{
		"SiteName":     siteName,
		"SiteIconHTML": iconHTML,
		"Name":         name,
		"NewPassword":  newPass,
		"ProfileURL":   profileURL,
	}

	subject := fmt.Sprintf("【%s】密码已被重置", siteName)
	textBody := fmt.Sprintf(
		"你好，%s，\n\n管理员已重置了你的账号密码，新密码：%s\n\n请登录后立即修改密码：\n%s\n\n%s 团队",
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
