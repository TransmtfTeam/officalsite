package email

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"time"
)

// Sender sends a plain-text email.
type Sender interface {
	Send(to, subject, body string) error
}

// New returns a Sender based on the email_provider setting.
// Recognised providers: "smtp", "resend". Any other value returns a no-op sender.
func New(settings map[string]string) Sender {
	switch settings["email_provider"] {
	case "smtp":
		return &smtpSender{
			host: settings["smtp_host"],
			port: settings["smtp_port"],
			user: settings["smtp_user"],
			pass: settings["smtp_pass"],
			from: settings["smtp_from"],
		}
	case "resend":
		return &resendSender{
			apiKey: settings["resend_api_key"],
			from:   settings["resend_from"],
		}
	default:
		return noopSender{}
	}
}


type noopSender struct{}

func (noopSender) Send(_, _, _ string) error { return nil }


type smtpSender struct {
	host, port, user, pass, from string
}

func (s *smtpSender) Send(to, subject, body string) error {
	port := s.port
	if port == "" {
		port = "587"
	}
	addr := net.JoinHostPort(s.host, port)
	msg := buildMessage(s.from, to, subject, body)

	if port == "465" {
		return s.sendViaTLS(addr, to, msg)
	}
	// STARTTLS path (port 587, 25, etc.)
	var auth smtp.Auth
	if s.user != "" {
		auth = smtp.PlainAuth("", s.user, s.pass, s.host)
	}
	return smtp.SendMail(addr, auth, s.from, []string{to}, msg)
}

func (s *smtpSender) sendViaTLS(addr, to string, msg []byte) error {
	tlsCfg := &tls.Config{ServerName: s.host}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("smtp tls dial: %w", err)
	}
	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return fmt.Errorf("smtp new client: %w", err)
	}
	defer c.Quit() //nolint:errcheck
	if s.user != "" {
		if err := c.Auth(smtp.PlainAuth("", s.user, s.pass, s.host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(s.from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err = wc.Write(msg); err != nil {
		return err
	}
	return wc.Close()
}


type resendSender struct {
	apiKey, from string
}

func (s *resendSender) Send(to, subject, body string) error {
	payload, err := json.Marshal(map[string]any{
		"from":    s.from,
		"to":      []string{to},
		"subject": subject,
		"text":    body,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("resend: unexpected status %d", resp.StatusCode)
	}
	return nil
}


// buildMessage constructs a minimal RFC 5322 message with base64-encoded UTF-8 body.
func buildMessage(from, to, subject, body string) []byte {
	encSubject := mime.QEncoding.Encode("utf-8", subject)
	b64body := base64.StdEncoding.EncodeToString([]byte(body))

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: %s\r\n", from)
	fmt.Fprintf(&buf, "To: %s\r\n", to)
	fmt.Fprintf(&buf, "Subject: %s\r\n", encSubject)
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	buf.WriteString("Content-Transfer-Encoding: base64\r\n")
	buf.WriteString("\r\n")
	// RFC 2045 搂6.8: base64 lines must not exceed 76 characters.
	for len(b64body) > 0 {
		n := 76
		if n > len(b64body) {
			n = len(b64body)
		}
		buf.WriteString(b64body[:n])
		buf.WriteString("\r\n")
		b64body = b64body[n:]
	}
	return buf.Bytes()
}
