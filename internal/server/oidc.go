package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCConfig configures interactive Single Sign-On.
type OIDCConfig struct {
	Issuer       string   `yaml:"issuer"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	RedirectURL  string   `yaml:"redirect_url"`
	GroupsClaim  string   `yaml:"groups_claim,omitempty"`
	AdminGroups  []string `yaml:"admin_groups,omitempty"`
	// CookieKey signs session cookies; when empty a random key is generated
	// at startup (restart then invalidates existing sessions).
	CookieKey string `yaml:"cookie_key,omitempty"`
}

func (c *OIDCConfig) validate() error {
	switch {
	case c.Issuer == "":
		return errors.New("oidc: issuer is required")
	case c.ClientID == "":
		return errors.New("oidc: client_id is required")
	case c.RedirectURL == "":
		return errors.New("oidc: redirect_url is required")
	}
	return nil
}

// groupsClaim returns the configured groups claim name or the default.
func (c *OIDCConfig) groupsClaim() string {
	if c.GroupsClaim != "" {
		return c.GroupsClaim
	}
	return "groups"
}

// oidcProvider is the configured Relying Party.
type oidcProvider struct {
	cfg      *OIDCConfig
	verifier *oidc.IDTokenVerifier
	oauth    oauth2.Config
	signKey  []byte
}

// newOIDCProvider performs OIDC discovery against the issuer and builds the
// Relying Party. It needs network access to the issuer at startup.
func newOIDCProvider(ctx context.Context, cfg *OIDCConfig) (*oidcProvider, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	key := []byte(cfg.CookieKey)
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
	}
	return &oidcProvider{
		cfg:      cfg,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
		},
		signKey: key,
	}, nil
}

const (
	sessionCookie = "hsmdoctor_session"
	flowCookie    = "hsmdoctor_oidc_flow"
)

// session is the signed cookie payload for an authenticated user.
type session struct {
	Subject string `json:"sub"`
	Role    string `json:"role"`
	Expiry  int64  `json:"exp"`
}

// flowState carries CSRF/replay/PKCE material across the redirect.
type flowState struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
}

// sign returns value + "." + base64(HMAC(value)).
func (p *oidcProvider) sign(value []byte) string {
	mac := hmac.New(sha256.New, p.signKey)
	mac.Write(value)
	return base64.RawURLEncoding.EncodeToString(value) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// unsign verifies and returns the payload of a signed cookie value.
func (p *oidcProvider) unsign(cookie string) ([]byte, error) {
	parts := splitDot(cookie)
	if parts == nil {
		return nil, errors.New("malformed cookie")
	}
	value, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	gotMAC, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, p.signKey)
	mac.Write(value)
	if subtle.ConstantTimeCompare(gotMAC, mac.Sum(nil)) != 1 {
		return nil, errors.New("bad cookie signature")
	}
	return value, nil
}

func splitDot(s string) []string {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return nil
}

// sessionFromRequest returns the valid, unexpired session or nil.
func (p *oidcProvider) sessionFromRequest(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	raw, err := p.unsign(c.Value)
	if err != nil {
		return nil
	}
	var s session
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	if time.Now().Unix() >= s.Expiry {
		return nil
	}
	return &s
}

func randToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// registerAuth wires the interactive login endpoints.
func (p *oidcProvider) registerAuth(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/login", p.handleLogin)
	mux.HandleFunc("GET /auth/callback", p.handleCallback)
	mux.HandleFunc("GET /auth/logout", p.handleLogout)
}

func (p *oidcProvider) handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := randToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	nonce, err := randToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	verifier := oauth2.GenerateVerifier()
	fs := flowState{State: state, Nonce: nonce, Verifier: verifier}
	raw, _ := json.Marshal(fs)
	http.SetCookie(w, &http.Cookie{
		Name: flowCookie, Value: p.sign(raw), Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		MaxAge: 600,
	})
	url := p.oauth.AuthCodeURL(fs.State,
		oidc.Nonce(fs.Nonce), oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, url, http.StatusFound)
}

func (p *oidcProvider) handleCallback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(flowCookie)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("missing login flow cookie"))
		return
	}
	raw, err := p.unsign(c.Value)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var fs flowState
	if err := json.Unmarshal(raw, &fs); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")), []byte(fs.State)) != 1 {
		writeError(w, http.StatusBadRequest, errors.New("state mismatch"))
		return
	}

	oauth2Token, err := p.oauth.Exchange(r.Context(), r.URL.Query().Get("code"),
		oauth2.VerifierOption(fs.Verifier))
	if err != nil {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("token exchange: %w", err))
		return
	}
	rawID, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("no id_token in response"))
		return
	}
	idToken, err := p.verifier.Verify(r.Context(), rawID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("verifying id_token: %w", err))
		return
	}
	if idToken.Nonce != fs.Nonce {
		writeError(w, http.StatusUnauthorized, errors.New("nonce mismatch"))
		return
	}

	role := p.roleFromClaims(idToken)
	s := session{Subject: idToken.Subject, Role: role, Expiry: idToken.Expiry.Unix()}
	sraw, _ := json.Marshal(s)
	// The session cookie is SameSite=Strict so it is never sent on
	// cross-site requests — this prevents a malicious page from triggering
	// state-changing API calls (e.g. a scan) via the operator's browser.
	// The flow cookie stays Lax because it must survive the top-level
	// redirect back from the identity provider.
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: p.sign(sraw), Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
		Expires: idToken.Expiry,
	})
	// Clear the transient flow cookie.
	http.SetCookie(w, &http.Cookie{Name: flowCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (p *oidcProvider) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// roleFromClaims maps the token's groups to a role: admin when any group is
// in AdminGroups, otherwise viewer.
func (p *oidcProvider) roleFromClaims(idToken *oidc.IDToken) string {
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return RoleViewer
	}
	groups := stringSlice(claims[p.cfg.groupsClaim()])
	for _, g := range groups {
		for _, admin := range p.cfg.AdminGroups {
			if g == admin {
				return RoleAdmin
			}
		}
	}
	return RoleViewer
}

// stringSlice coerces a JSON claim (which may be []any of strings, or a
// single string) into a string slice.
func stringSlice(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{t}
	default:
		return nil
	}
}
