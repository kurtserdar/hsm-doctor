package server_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/server"
	"github.com/kurtserdar/hsm-doctor/internal/store"
)

const (
	adminToken  = "admin-token-0123456789"
	viewerToken = "viewer-token-0123456789"
)

func newAuthedCentral(t *testing.T) *httptest.Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	srv := server.NewCentral("test", st, "enroll-secret-123")
	t.Cleanup(srv.Close)

	cfg, err := server.LoadAuthConfig([]byte(`
tokens:
  - name: ops
    token: ` + adminToken + `
    role: admin
  - name: dashboard
    token: ` + viewerToken + `
    role: viewer
`))
	if err != nil {
		t.Fatalf("LoadAuthConfig: %v", err)
	}
	srv.SetAuth(cfg)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func do(t *testing.T, method, url, token string, body string) *http.Response {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestAuthMiddleware(t *testing.T) {
	ts := newAuthedCentral(t)

	cases := []struct {
		name   string
		method string
		path   string
		token  string
		body   string
		want   int
	}{
		{"no token rejected", "GET", "/api/v1/hsms", "", "", 401},
		{"wrong token rejected", "GET", "/api/v1/hsms", "bogus-token-0123456789", "", 401},
		{"viewer can read", "GET", "/api/v1/hsms", viewerToken, "", 200},
		{"viewer cannot post", "POST", "/api/v1/diff", viewerToken, `{}`, 403},
		{"admin can read", "GET", "/api/v1/info", adminToken, "", 200},
		// Admin POST to diff with empty snapshots is a 400 (bad input), not
		// an auth failure: authorization passed.
		{"admin can post", "POST", "/api/v1/diff", adminToken, `{}`, 400},
		{"metrics protected", "GET", "/metrics", "", "", 401},
		{"metrics with viewer", "GET", "/metrics", viewerToken, "", 200},
		{"ui stays open", "GET", "/", "", "", 200},
		// Agent ingest endpoints use their own credentials: the user-auth
		// layer must not block enrollment (it fails later on its own check).
		{"ingest exempt from user auth", "POST", "/api/v1/ingest/enroll", "",
			`{"name":"a","enroll_token":"wrong"}`, 401},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := do(t, c.method, ts.URL+c.path, c.token, c.body)
			if resp.StatusCode != c.want {
				t.Errorf("%s %s: want %d, got %d", c.method, c.path, c.want, resp.StatusCode)
			}
		})
	}

	// The ingest exemption must actually reach the enrollment handler:
	// correct enrollment token succeeds without any user bearer token.
	resp := do(t, "POST", ts.URL+"/api/v1/ingest/enroll", "",
		`{"name":"agent-x","enroll_token":"enroll-secret-123"}`)
	if resp.StatusCode != 200 {
		t.Errorf("enrollment with valid token should bypass user auth, got %d", resp.StatusCode)
	}
}

func TestLoadAuthConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"empty", "tokens: []", "no tokens"},
		{"short token", "tokens:\n  - {token: short, role: admin}", "shorter than 16"},
		{"bad role", "tokens:\n  - {token: 0123456789abcdef, role: root}", "invalid role"},
		{"unknown field", "tokens:\n  - {token: 0123456789abcdef, role: admin, extra: x}", "field extra not found"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := server.LoadAuthConfig([]byte(c.yaml))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("want error containing %q, got %v", c.want, err)
			}
		})
	}
}
