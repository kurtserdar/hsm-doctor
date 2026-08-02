// Package notify delivers operational alerts (drift, certificate expiry) to
// humans by e-mail, complementing the machine-oriented webhook.
package notify

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// TLSMode selects how the SMTP connection is secured.
type TLSMode string

const (
	// TLSStartTLS upgrades a plaintext connection (typically port 587).
	TLSStartTLS TLSMode = "starttls"
	// TLSImplicit dials TLS directly (typically port 465).
	TLSImplicit TLSMode = "implicit"
	// TLSNone sends over plaintext (lab/relay-on-localhost only).
	TLSNone TLSMode = "none"
)

// SMTPConfig configures the SMTP transport.
type SMTPConfig struct {
	Host     string   `yaml:"host"`
	Port     int      `yaml:"port"`
	Username string   `yaml:"username,omitempty"`
	Password string   `yaml:"password,omitempty"`
	From     string   `yaml:"from"`
	To       []string `yaml:"to"`
	TLS      TLSMode  `yaml:"tls,omitempty"`
}

// Config is the parsed --notify-config document.
type Config struct {
	SMTP SMTPConfig `yaml:"smtp"`
	// Triggers select which events send mail; both default to true when the
	// notify config is present.
	Drift      *bool `yaml:"drift,omitempty"`
	Regression *bool `yaml:"regression,omitempty"`
	CertExpiry *bool `yaml:"cert_expiry,omitempty"`
	// CertWarnDays are the day thresholds at which an expiring certificate
	// first triggers a mail; defaults to 30, 14, 1.
	CertWarnDays []int `yaml:"cert_warn_days,omitempty"`
}

// LoadConfig reads and validates a notify configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading notify config: %w", err)
	}
	return parseConfig(data)
}

// parseConfig parses and validates a notify config document.
func parseConfig(data []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing notify config: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	switch {
	case c.SMTP.Host == "":
		return fmt.Errorf("notify: smtp.host is required")
	case c.SMTP.Port == 0:
		return fmt.Errorf("notify: smtp.port is required")
	case c.SMTP.From == "":
		return fmt.Errorf("notify: smtp.from is required")
	case len(c.SMTP.To) == 0:
		return fmt.Errorf("notify: at least one smtp.to recipient is required")
	}
	if c.SMTP.TLS == "" {
		c.SMTP.TLS = TLSStartTLS
	}
	switch c.SMTP.TLS {
	case TLSStartTLS, TLSImplicit, TLSNone:
	default:
		return fmt.Errorf("notify: invalid smtp.tls %q (want starttls, implicit or none)", c.SMTP.TLS)
	}
	return nil
}

// DriftEnabled reports whether drift notifications are on (default true).
func (c *Config) DriftEnabled() bool { return c.Drift == nil || *c.Drift }

// RegressionEnabled reports whether posture-regression notifications are on
// (default true).
func (c *Config) RegressionEnabled() bool { return c.Regression == nil || *c.Regression }

// CertExpiryEnabled reports whether cert-expiry notifications are on
// (default true).
func (c *Config) CertExpiryEnabled() bool { return c.CertExpiry == nil || *c.CertExpiry }

// warnDays returns the configured thresholds or the defaults, high to low.
func (c *Config) warnDays() []int {
	if len(c.CertWarnDays) > 0 {
		return c.CertWarnDays
	}
	return []int{30, 14, 1}
}

// Mailer sends a plain-text message to one or more recipients.
type Mailer interface {
	Send(subject, body string, to []string) error
}

// addr returns host:port.
func (c SMTPConfig) addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// buildMessage assembles an RFC 5322 message.
func buildMessage(from string, to []string, subject, body string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(&b, "\r\n")
	// Normalize line endings to CRLF.
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	return b.Bytes()
}
