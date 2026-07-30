package server_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/kurtserdar/hsm-doctor/internal/server"
	"github.com/kurtserdar/hsm-doctor/internal/store"
)

// mockIdP is a minimal OIDC provider: discovery, JWKS, and a token endpoint
// that mints an ID token with configurable groups for the last login.
type mockIdP struct {
	url         string
	key         *rsa.PrivateKey
	keyID       string
	clientID    string
	nextGroups  []string
	nextSubject string
	nonce       string
}

func newMockIdP(t *testing.T, clientID string) *mockIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &mockIdP{key: key, keyID: "test-key", clientID: clientID, nextSubject: "user-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSONRaw(w, map[string]any{
			"issuer":                                idp.url,
			"authorization_endpoint":                idp.url + "/authorize",
			"token_endpoint":                        idp.url + "/token",
			"jwks_uri":                              idp.url + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &idp.key.PublicKey, KeyID: idp.keyID, Algorithm: "RS256", Use: "sig",
		}}}
		writeJSONRaw(w, jwks)
	})
	// authorize redirects straight back to the RP callback with a code,
	// echoing state and remembering the nonce for the ID token.
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		idp.nonce = r.URL.Query().Get("nonce")
		redirect := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		http.Redirect(w, r, redirect+"?code=test-code&state="+state, http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		writeJSONRaw(w, map[string]any{
			"access_token": "test-access",
			"token_type":   "Bearer",
			"id_token":     idp.mintIDToken(t),
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	idp.url = srv.URL
	return idp
}

func (idp *mockIdP) mintIDToken(t *testing.T) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: idp.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", idp.keyID))
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"iss":    idp.url,
		"sub":    idp.nextSubject,
		"aud":    idp.clientID,
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
		"nonce":  idp.nonce,
		"groups": idp.nextGroups,
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func writeJSONRaw(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// startOIDCServer boots a central server with OIDC + a static token. It
// pre-allocates the listener so the redirect URL is known before SetAuth,
// matching real startup order (auth configured before the handler is built).
func startOIDCServer(t *testing.T, idp *mockIdP) *httptest.Server {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/oidc.db")
	if err != nil {
		t.Fatal(err)
	}
	srv := server.NewCentral("test", st, "")
	t.Cleanup(srv.Close)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	cfg := &server.AuthConfig{
		Tokens: []server.AuthToken{{Name: "ci", Token: "static-admin-token-0123456789", Role: server.RoleAdmin}},
		OIDC: &server.OIDCConfig{
			Issuer:      idp.url,
			ClientID:    idp.clientID,
			RedirectURL: "https://" + addr + "/auth/callback",
			AdminGroups: []string{"hsm-admins"},
			CookieKey:   "test-cookie-signing-key-0123456789",
		},
	}
	if err := srv.SetAuth(cfg); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}

	ts := httptest.NewUnstartedServer(srv.Handler())
	_ = ts.Listener.Close()
	ts.Listener = ln
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func TestOIDCLoginFlowAndRoleMapping(t *testing.T) {
	idp := newMockIdP(t, "hsmdoctor")
	ts := startOIDCServer(t, idp)

	jar, _ := cookiejar.New(nil)
	client := ts.Client()
	client.Jar = jar
	// Don't auto-follow into the IdP's /authorize; drive it manually so the
	// IdP and RP share the same client (and cookie jar).
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }

	// 1. Unauthenticated API call → 401.
	resp, err := client.Get(ts.URL + "/api/v1/hsms")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated API: want 401, got %d", resp.StatusCode)
	}

	// 2. Log in as an admin-group member; follow the whole redirect chain.
	idp.nextGroups = []string{"staff", "hsm-admins"}
	client.CheckRedirect = nil // follow redirects through login → IdP → callback
	resp, err = client.Get(ts.URL + "/auth/login")
	if err != nil {
		t.Fatalf("login flow: %v", err)
	}
	resp.Body.Close()

	// 3. Now the session cookie grants admin: a POST (diff) is authorized
	//    (400 for empty body, but NOT 401/403).
	resp, err = client.Post(ts.URL+"/api/v1/diff", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		t.Errorf("admin session should authorize POST, got %d", resp.StatusCode)
	}

	// 4. Logout clears the session; API is protected again.
	resp, err = client.Get(ts.URL + "/auth/logout")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = client.Get(ts.URL + "/api/v1/hsms")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("after logout API should be 401, got %d", resp.StatusCode)
	}
}

func TestOIDCViewerCannotModify(t *testing.T) {
	idp := newMockIdP(t, "hsmdoctor")
	ts := startOIDCServer(t, idp)
	jar, _ := cookiejar.New(nil)
	client := ts.Client()
	client.Jar = jar

	// A user outside the admin groups becomes a viewer.
	idp.nextGroups = []string{"staff"}
	if resp, err := client.Get(ts.URL + "/auth/login"); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
	}

	// GET allowed...
	resp, err := client.Get(ts.URL + "/api/v1/hsms")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("viewer GET should be 200, got %d", resp.StatusCode)
	}
	// ...POST forbidden.
	resp, err = client.Post(ts.URL+"/api/v1/diff", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer POST should be 403, got %d", resp.StatusCode)
	}
}

func TestStaticTokenStillWorksWithOIDC(t *testing.T) {
	idp := newMockIdP(t, "hsmdoctor")
	ts := startOIDCServer(t, idp)
	client := ts.Client()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/hsms", nil)
	req.Header.Set("Authorization", "Bearer static-admin-token-0123456789")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("static admin token should still work alongside OIDC, got %d", resp.StatusCode)
	}
}

func TestInfoAdvertisesOIDC(t *testing.T) {
	idp := newMockIdP(t, "hsmdoctor")
	ts := startOIDCServer(t, idp)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/info", nil)
	req.Header.Set("Authorization", "Bearer static-admin-token-0123456789")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["oidc"] != true {
		t.Errorf("/info should advertise oidc=true, got %v", out["oidc"])
	}
}
