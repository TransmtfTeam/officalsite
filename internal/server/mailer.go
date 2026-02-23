package server

import (
	"context"
	"fmt"
	"log"

	"transmtf.com/oidc/internal/email"
)

// mailer builds an email.Sender from the current site settings.
func (h *Handler) mailer(ctx context.Context) email.Sender {
	return email.New(h.st.GetAllSettings(ctx))
}

// sendWelcomeEmail sends a registration welcome message. Errors are logged, not returned.
func (h *Handler) sendWelcomeEmail(ctx context.Context, toEmail, name string) {
	siteName := orDefault(h.st.GetSetting(ctx, "site_name"), "Team TransMTF")
	subject := "Welcome to " + siteName
	body := fmt.Sprintf(
		"Hello %s,\n\nWelcome to %s.\n\nYou can now sign in and complete your profile:\n%s/profile\n\nRegards,\n%s Team",
		name, siteName, h.cfg.Issuer, siteName,
	)
	if err := h.mailer(ctx).Send(toEmail, subject, body); err != nil {
		log.Printf("email: welcome to %s: %v", toEmail, err)
	}
}

// sendPasswordResetEmail notifies a user that their password was reset by an admin.
func (h *Handler) sendPasswordResetEmail(ctx context.Context, toEmail, name, newPass string) {
	siteName := orDefault(h.st.GetSetting(ctx, "site_name"), "Team TransMTF")
	subject := fmt.Sprintf("[%s] Your password has been reset", siteName)
	body := fmt.Sprintf(
		"Hello %s,\n\nAn administrator has reset your account password.\n\nNew password: %s\n\nPlease sign in and change it as soon as possible:\n%s/profile\n\nRegards,\n%s Team",
		name, newPass, h.cfg.Issuer, siteName,
	)
	if err := h.mailer(ctx).Send(toEmail, subject, body); err != nil {
		log.Printf("email: password reset to %s: %v", toEmail, err)
	}
}
