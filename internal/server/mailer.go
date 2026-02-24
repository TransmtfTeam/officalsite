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
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:24px;background:#f5f7fb;font-family:Segoe UI,Roboto,sans-serif;color:#1f2937">
  <div style="max-width:560px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:28px">
    <div style="text-align:center;margin-bottom:18px">
      {{SiteIconHTML}}
      <h1 style="margin:0;font-size:22px">{{SiteName}}</h1>
    </div>
    <h2 style="margin:0 0 10px;font-size:20px">Welcome to {{SiteName}}</h2>
    <p style="margin:0 0 16px;line-height:1.7">Hello {{Name}}, your account is ready.</p>
    <p style="margin:0 0 22px;line-height:1.7">You can complete your profile using the button below.</p>
    <a href="{{ProfileURL}}" style="display:inline-block;background:#2563eb;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none">Open Profile</a>
    <p style="margin:24px 0 0;font-size:13px;color:#6b7280">{{SiteName}} system email. Please do not reply.</p>
  </div>
</body>
</html>`

// defaultPasswordResetHTML is the styled HTML template for password reset emails.
// Placeholders: {{SiteName}}, {{SiteIconHTML}}, {{Name}}, {{NewPassword}}, {{ProfileURL}}
const defaultPasswordResetHTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:24px;background:#f5f7fb;font-family:Segoe UI,Roboto,sans-serif;color:#1f2937">
  <div style="max-width:560px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:28px">
    <div style="text-align:center;margin-bottom:18px">
      {{SiteIconHTML}}
      <h1 style="margin:0;font-size:22px">{{SiteName}}</h1>
    </div>
    <h2 style="margin:0 0 10px;font-size:20px">Password was reset</h2>
    <p style="margin:0 0 16px;line-height:1.7">Hello {{Name}}, an administrator reset your password.</p>
    <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:12px 14px;margin-bottom:18px;text-align:center">
      <code style="font-size:18px;font-weight:700">{{NewPassword}}</code>
    </div>
    <p style="margin:0 0 20px;line-height:1.7">Please sign in and change this password immediately.</p>
    <a href="{{ProfileURL}}" style="display:inline-block;background:#2563eb;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none">Change Password</a>
    <p style="margin:24px 0 0;font-size:13px;color:#6b7280">{{SiteName}} system email. Please do not reply.</p>
  </div>
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
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:24px;background:#f5f7fb;font-family:Segoe UI,Roboto,sans-serif;color:#1f2937">
  <div style="max-width:560px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:28px">
    <div style="text-align:center;margin-bottom:18px">
      {{SiteIconHTML}}
      <h1 style="margin:0;font-size:22px">{{SiteName}}</h1>
    </div>
    <h2 style="margin:0 0 10px;font-size:20px">Verify your email</h2>
    <p style="margin:0 0 18px;line-height:1.7">Hello {{Name}}, click below to verify your email. This link expires in 24 hours.</p>
    <a href="{{VerifyURL}}" style="display:inline-block;background:#2563eb;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none">Verify Email</a>
    <p style="margin:20px 0 0;font-size:13px;color:#6b7280">If the button does not work, open this URL:</p>
    <p style="margin:8px 0 0;font-size:13px;word-break:break-all;color:#374151">{{VerifyURL}}</p>
    <p style="margin:24px 0 0;font-size:13px;color:#6b7280">{{SiteName}} system email. Please do not reply.</p>
  </div>
</body>
</html>`

// defaultForgotPasswordHTML is the styled HTML template for password reset links.
// Placeholders: {{SiteName}}, {{SiteIconHTML}}, {{Name}}, {{ResetURL}}
const defaultForgotPasswordHTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:24px;background:#f5f7fb;font-family:Segoe UI,Roboto,sans-serif;color:#1f2937">
  <div style="max-width:560px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:28px">
    <div style="text-align:center;margin-bottom:18px">
      {{SiteIconHTML}}
      <h1 style="margin:0;font-size:22px">{{SiteName}}</h1>
    </div>
    <h2 style="margin:0 0 10px;font-size:20px">Reset your password</h2>
    <p style="margin:0 0 18px;line-height:1.7">Hello {{Name}}, click below to reset your password. This link expires in 30 minutes.</p>
    <a href="{{ResetURL}}" style="display:inline-block;background:#2563eb;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none">Reset Password</a>
    <p style="margin:20px 0 0;font-size:13px;color:#6b7280">If the button does not work, open this URL:</p>
    <p style="margin:8px 0 0;font-size:13px;word-break:break-all;color:#374151">{{ResetURL}}</p>
    <p style="margin:24px 0 0;font-size:13px;color:#6b7280">{{SiteName}} system email. Please do not reply.</p>
  </div>
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

	subject := "[" + siteName + "] Verify your email"
	textBody := "Hello " + name + ",\n\nPlease verify your email by opening the link below (valid for 24 hours):\n" + verifyURL + "\n\n" + siteName + " Team"
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

	subject := "[" + siteName + "] Reset password"
	textBody := "Hello " + name + ",\n\nReset your password using the link below (valid for 30 minutes):\n" + resetURL + "\n\n" + siteName + " Team"
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
		"SiteName":     siteName,
		"SiteIconHTML": iconHTML,
		"Name":         name,
		"ProfileURL":   profileURL,
	}

	subject := "Welcome to " + siteName
	textBody := fmt.Sprintf(
		"Hello %s,\n\nWelcome to %s.\n\nComplete your profile here:\n%s\n\n%s Team",
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

	subject := fmt.Sprintf("[%s] Password reset", siteName)
	textBody := fmt.Sprintf(
		"Hello %s,\n\nAn administrator reset your account password.\nNew password: %s\n\nPlease sign in and change it immediately:\n%s\n\n%s Team",
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
