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

// Sender sends emails. SendHTML sends a multipart message with both plain-text
// and HTML bodies; if htmlBody is empty it falls back to plain-text only.
type Sender interface {
	Send(to, subject, body string) error
	SendHTML(to, subject, textBody, htmlBody string) error
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

func (noopSender) Send(_, _, _ string) error                { return nil }
func (noopSender) SendHTML(_, _, _, _ string) error         { return nil }


type smtpSender struct {
	host, port, user, pass, from string
}

func (s *smtpSender) Send(to, subject, body string) error {
	return s.SendHTML(to, subject, body, "")
}

func (s *smtpSender) SendHTML(to, subject, textBody, htmlBody string) error {
	port := s.port
	if port == "" {
		port = "587"
	}
	addr := net.JoinHostPort(s.host, port)
	var msg []byte
	if htmlBody != "" {
		msg = buildMixedMessage(s.from, to, subject, textBody, htmlBody)
	} else {
		msg = buildMessage(s.from, to, subject, textBody)
	}

	if port == "465" {
		return s.sendViaTLS(addr, to, msg)
	}
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
	return s.SendHTML(to, subject, body, "")
}

func (s *resendSender) SendHTML(to, subject, textBody, htmlBody string) error {
	payload := map[string]any{
		"from":    s.from,
		"to":      []string{to},
		"subject": subject,
		"text":    textBody,
	}
	if htmlBody != "" {
		payload["html"] = htmlBody
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(data))
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


// buildMessage constructs a minimal RFC 5322 plain-text message.
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

// buildMixedMessage builds a multipart/alternative message with text and HTML parts.
func buildMixedMessage(from, to, subject, textBody, htmlBody string) []byte {
	const boundary = "==_TMTF_BOUNDARY_=="
	encSubject := mime.QEncoding.Encode("utf-8", subject)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: %s\r\n", from)
	fmt.Fprintf(&buf, "To: %s\r\n", to)
	fmt.Fprintf(&buf, "Subject: %s\r\n", encSubject)
	buf.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&buf, "Content-Type: multipart/alternative; boundary=%q\r\n", boundary)
	buf.WriteString("\r\n")

	// Plain-text part
	fmt.Fprintf(&buf, "--%s\r\n", boundary)
	buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	buf.WriteString("Content-Transfer-Encoding: base64\r\n")
	buf.WriteString("\r\n")
	writeBase64(&buf, textBody)

	// HTML part
	fmt.Fprintf(&buf, "--%s\r\n", boundary)
	buf.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	buf.WriteString("Content-Transfer-Encoding: base64\r\n")
	buf.WriteString("\r\n")
	writeBase64(&buf, htmlBody)

	fmt.Fprintf(&buf, "--%s--\r\n", boundary)
	return buf.Bytes()
}

func writeBase64(buf *bytes.Buffer, s string) {
	b64 := base64.StdEncoding.EncodeToString([]byte(s))
	for len(b64) > 0 {
		n := 76
		if n > len(b64) {
			n = len(b64)
		}
		buf.WriteString(b64[:n])
		buf.WriteString("\r\n")
		b64 = b64[n:]
	}
}
