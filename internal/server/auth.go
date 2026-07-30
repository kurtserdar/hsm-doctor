package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"
)

// Roles for API tokens.
const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

// AuthToken is one API credential. The token value lives in the config
// file, which must be protected like any credential store (0600).
type AuthToken struct {
	Name  string `yaml:"name"`
	Token string `yaml:"token"`
	Role  string `yaml:"role"`
}

// AuthConfig is the parsed authentication configuration.
type AuthConfig struct {
	Tokens []AuthToken `yaml:"tokens"`
	// OIDC, when set, enables interactive Single Sign-On for the web UI and
	// API alongside any static tokens.
	OIDC *OIDCConfig `yaml:"oidc,omitempty"`
}

// LoadAuthConfig parses and validates an auth config document.
func LoadAuthConfig(data []byte) (*AuthConfig, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg AuthConfig
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing auth config: %w", err)
	}
	if len(cfg.Tokens) == 0 && cfg.OIDC == nil {
		return nil, errors.New("auth config must define tokens, oidc, or both")
	}
	for i, t := range cfg.Tokens {
		if t.Token == "" {
			return nil, fmt.Errorf("auth token #%d has an empty token value", i+1)
		}
		if len(t.Token) < 16 {
			return nil, fmt.Errorf("auth token #%d (%s) is shorter than 16 characters", i+1, t.Name)
		}
		if t.Role != RoleAdmin && t.Role != RoleViewer {
			return nil, fmt.Errorf("auth token #%d (%s) has invalid role %q (want admin or viewer)", i+1, t.Name, t.Role)
		}
	}
	if cfg.OIDC != nil {
		if err := cfg.OIDC.validate(); err != nil {
			return nil, err
		}
	}
	return &cfg, nil
}

// roleFor resolves a presented bearer token to its role using
// constant-time comparison; empty when unknown.
func (c *AuthConfig) roleFor(presented string) string {
	presentedHash := sha256.Sum256([]byte(presented))
	role := ""
	for _, t := range c.Tokens {
		tokenHash := sha256.Sum256([]byte(t.Token))
		if subtle.ConstantTimeCompare(presentedHash[:], tokenHash[:]) == 1 {
			role = t.Role
		}
	}
	return role
}

// authMiddleware enforces API authentication when configured.
//
// Exempt paths:
//   - /api/v1/ingest/*: agents authenticate with their own tokens.
//   - static UI assets: public application code; all data flows through
//     the protected API.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	if s.auth == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		protected := strings.HasPrefix(path, "/api/") || path == "/metrics"
		// /api/v1/info is an unauthenticated discovery endpoint (tool
		// version, mode and whether SSO is available) so the UI can render
		// the right sign-in options before the user authenticates.
		exempt := strings.HasPrefix(path, "/api/v1/ingest/") || path == "/api/v1/info"
		if !protected || exempt {
			next.ServeHTTP(w, r)
			return
		}

		// Resolve the caller's role from an OIDC session cookie first, then
		// a static bearer token. Either source is accepted.
		role := ""
		if s.oidc != nil {
			if sess := s.oidc.sessionFromRequest(r); sess != nil {
				role = sess.Role
			}
		}
		if role == "" {
			if token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && token != "" {
				role = s.auth.roleFor(token)
			}
		}

		switch role {
		case RoleAdmin:
			next.ServeHTTP(w, r)
		case RoleViewer:
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}
			writeError(w, http.StatusForbidden, errors.New("viewer role cannot modify or execute; admin role required"))
		default:
			writeError(w, http.StatusUnauthorized, errors.New("authentication required (SSO session or bearer token)"))
		}
	})
}
