//go:build integration

package server_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/server"
	"github.com/kurtserdar/hsm-doctor/internal/testutil"
	"github.com/kurtserdar/hsm-doctor/rules"
)

// newTestServer boots a server over a fresh SoftHSM token with one weak RSA
// key and one expired certificate.
func newTestServer(t *testing.T) (*httptest.Server, uint) {
	t.Helper()
	client, slot := testutil.NewSoftHSM(t)

	sess, err := client.OpenSession(slot, testutil.UserPIN, true)
	if err != nil {
		t.Fatalf("opening session: %v", err)
	}
	testutil.GenerateRSAKeyPair(t, sess, testutil.KeyPairOpts{
		Label: "weak-key", ID: []byte{0x01}, Bits: 1024, Extractable: true,
	})
	testutil.ImportSelfSignedCert(t, sess, "dead-cert", []byte{0x02}, "dead.test",
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	sess.Close()
	client.Close() // the server opens its own module handle

	cfg, err := policy.Load(rules.Default)
	if err != nil {
		t.Fatalf("loading rules: %v", err)
	}
	srv, err := server.New(testutil.ModulePath(t), testutil.UserPIN, cfg, "test")
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	t.Cleanup(srv.Close)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, slot
}

func getJSON(t *testing.T, url string, wantStatus int) map[string]any {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		t.Fatalf("GET %s: status %d, want %d", url, resp.StatusCode, wantStatus)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding %s: %v", url, err)
	}
	return out
}

func TestAPIEndpoints(t *testing.T) {
	ts, slot := newTestServer(t)

	t.Run("info", func(t *testing.T) {
		out := getJSON(t, ts.URL+"/api/v1/info", http.StatusOK)
		if out["tool"] != "hsmdoctor" {
			t.Errorf("info: %v", out)
		}
	})

	t.Run("discover", func(t *testing.T) {
		out := getJSON(t, ts.URL+"/api/v1/discover?mechanisms=true", http.StatusOK)
		if out["slots"] == nil || out["mechanisms"] == nil {
			t.Errorf("discover missing fields: %v", out)
		}
	})

	t.Run("scan", func(t *testing.T) {
		out := getJSON(t, fmt.Sprintf("%s/api/v1/slots/%d/scan", ts.URL, slot), http.StatusOK)
		score, ok := out["score"].(float64)
		if !ok || score >= 100 {
			t.Errorf("scan should report a reduced score, got %v", out["score"])
		}
		findings, _ := out["findings"].([]any)
		if len(findings) == 0 {
			t.Error("scan should produce findings for the weak extractable key")
		}
	})

	t.Run("certs", func(t *testing.T) {
		out := getJSON(t, fmt.Sprintf("%s/api/v1/slots/%d/certs", ts.URL, slot), http.StatusOK)
		counts, _ := out["counts"].(map[string]any)
		if counts == nil || counts["expired"].(float64) != 1 {
			t.Errorf("certs counts wrong: %v", out)
		}
	})

	t.Run("test profile", func(t *testing.T) {
		resp, err := http.Post(fmt.Sprintf("%s/api/v1/slots/%d/test", ts.URL, slot),
			"application/json", bytes.NewBufferString(`{"profile":"sign-verify"}`))
		if err != nil {
			t.Fatalf("POST test: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST test: status %d", resp.StatusCode)
		}
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		steps, _ := out["steps"].([]any)
		if len(steps) == 0 {
			t.Error("test run returned no steps")
		}
	})

	t.Run("bench bounded", func(t *testing.T) {
		resp, err := http.Post(fmt.Sprintf("%s/api/v1/slots/%d/bench", ts.URL, slot),
			"application/json", bytes.NewBufferString(`{"duration_ms":200,"max_ops":50,"sessions":1}`))
		if err != nil {
			t.Fatalf("POST bench: %v", err)
		}
		defer resp.Body.Close()
		var out struct {
			Measurements []struct {
				Ops int64 `json:"ops"`
			} `json:"measurements"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		for _, m := range out.Measurements {
			if m.Ops > 50 {
				t.Errorf("bench exceeded op budget: %d", m.Ops)
			}
		}
	})

	t.Run("diff", func(t *testing.T) {
		snapURL := fmt.Sprintf("%s/api/v1/slots/%d/snapshot", ts.URL, slot)
		snap1 := getJSONRaw(t, snapURL)
		snap2 := getJSONRaw(t, snapURL)
		body := fmt.Sprintf(`{"old":%s,"new":%s}`, snap1, snap2)
		resp, err := http.Post(ts.URL+"/api/v1/diff", "application/json", bytes.NewBufferString(body))
		if err != nil {
			t.Fatalf("POST diff: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST diff: status %d", resp.StatusCode)
		}
	})

	t.Run("invalid slot", func(t *testing.T) {
		out := getJSON(t, ts.URL+"/api/v1/slots/notanumber/scan", http.StatusBadRequest)
		if out["error"] == nil {
			t.Error("invalid slot should return a JSON error")
		}
	})

	t.Run("spa fallback", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/some/client/route")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("SPA fallback should serve index.html, got %d", resp.StatusCode)
		}
	})
}

func getJSONRaw(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}
