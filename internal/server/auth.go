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
}

// LoadAuthConfig parses and validates an auth config document.
func LoadAuthConfig(data []byte) (*AuthConfig, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg AuthConfig
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing auth config: %w", err)
	}
	if len(cfg.Tokens) == 0 {
		return nil, errors.New("auth config contains no tokens")
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
		exempt := strings.HasPrefix(path, "/api/v1/ingest/")
		if !protected || exempt {
			next.ServeHTTP(w, r)
			return
		}

		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			writeError(w, http.StatusUnauthorized, errors.New("missing bearer token"))
			return
		}
		switch s.auth.roleFor(token) {
		case RoleAdmin:
			next.ServeHTTP(w, r)
		case RoleViewer:
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}
			writeError(w, http.StatusForbidden, errors.New("viewer tokens cannot modify or execute; admin role required"))
		default:
			writeError(w, http.StatusUnauthorized, errors.New("invalid bearer token"))
		}
	})
}
