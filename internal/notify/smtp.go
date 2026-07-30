package notify

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
)

// smtpMailer sends mail over SMTP using the standard library, supporting
// STARTTLS (587), implicit TLS (465) and plaintext relays.
type smtpMailer struct {
	cfg SMTPConfig
}

// NewSMTPMailer builds a Mailer from the SMTP configuration.
func NewSMTPMailer(cfg SMTPConfig) Mailer {
	return &smtpMailer{cfg: cfg}
}

func (m *smtpMailer) auth() smtp.Auth {
	if m.cfg.Username == "" {
		return nil
	}
	return smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
}

func (m *smtpMailer) Send(subject, body string, to []string) error {
	if len(to) == 0 {
		to = m.cfg.To
	}
	msg := buildMessage(m.cfg.From, to, subject, body)

	switch m.cfg.TLS {
	case TLSImplicit:
		return m.sendImplicit(to, msg)
	default:
		// STARTTLS and none both use the plaintext dial; STARTTLS then
		// upgrades. smtp.SendMail issues STARTTLS automatically when the
		// server advertises it.
		return smtp.SendMail(m.cfg.addr(), m.auth(), m.cfg.From, to, msg)
	}
}

// sendImplicit dials a TLS connection first (port 465 style), then speaks
// SMTP over it.
func (m *smtpMailer) sendImplicit(to []string, msg []byte) error {
	conn, err := tls.Dial("tcp", m.cfg.addr(), &tls.Config{
		ServerName: m.cfg.Host,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return fmt.Errorf("dialing %s: %w", m.cfg.addr(), err)
	}
	defer func() { _ = conn.Close() }()

	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		return err
	}
	defer func() { _ = c.Quit() }()

	if auth := m.auth(); auth != nil {
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(m.cfg.From); err != nil {
		return err
	}
	for _, addr := range to {
		if err := c.Rcpt(addr); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	return w.Close()
}
