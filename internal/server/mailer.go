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
// Placeholders: {{SiteName}}, {{Name}}, {{ProfileURL}}
const defaultWelcomeHTML = `<!DOCTYPE html>
<html lang="zh">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f0f4f8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f4f8;padding:48px 16px">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08)">
  <tr>
    <td style="background:linear-gradient(135deg,#3b82f6 0%,#ec4899 100%);padding:32px 40px;text-align:center">
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
// Placeholders: {{SiteName}}, {{Name}}, {{NewPassword}}, {{ProfileURL}}
const defaultPasswordResetHTML = `<!DOCTYPE html>
<html lang="zh">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f0f4f8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f4f8;padding:48px 16px">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08)">
  <tr>
    <td style="background:linear-gradient(135deg,#3b82f6 0%,#ec4899 100%);padding:32px 40px;text-align:center">
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

// sendWelcomeEmail sends a registration welcome message.
func (h *Handler) sendWelcomeEmail(ctx context.Context, toEmail, name string) {
	siteName := orDefault(h.st.GetSetting(ctx, "site_name"), "Team TransMTF")
	profileURL := h.cfg.Issuer + "/profile"

	vars := map[string]string{
		"SiteName":   siteName,
		"Name":       name,
		"ProfileURL": profileURL,
	}

	subject := "Welcome to " + siteName
	textBody := fmt.Sprintf(
		"Hello %s,\n\nWelcome to %s.\n\nSign in and complete your profile:\n%s\n\nRegards,\n%s Team",
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

	vars := map[string]string{
		"SiteName":    siteName,
		"Name":        name,
		"NewPassword": newPass,
		"ProfileURL":  profileURL,
	}

	subject := fmt.Sprintf("[%s] Your password has been reset", siteName)
	textBody := fmt.Sprintf(
		"Hello %s,\n\nAn administrator has reset your account password.\n\nNew password: %s\n\nPlease sign in and change it:\n%s\n\nRegards,\n%s Team",
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
