//go:build integration

package agent_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/agent"
	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/server"
	"github.com/kurtserdar/hsm-doctor/internal/store"
	"github.com/kurtserdar/hsm-doctor/internal/testutil"
	"github.com/kurtserdar/hsm-doctor/rules"
)

const enrollToken = "it-enroll-secret"

func newCentral(t *testing.T) (*httptest.Server, store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "fleet.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	srv := server.NewCentral("test", st, enrollToken)
	t.Cleanup(srv.Close)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, st
}

func TestAgentEnrollAndPush(t *testing.T) {
	p11client, slot := testutil.NewSoftHSM(t)

	sess, err := p11client.OpenSession(slot, testutil.UserPIN, true)
	if err != nil {
		t.Fatalf("opening session: %v", err)
	}
	testutil.GenerateRSAKeyPair(t, sess, testutil.KeyPairOpts{
		Label: "fleet-key", ID: []byte{0x01}, Bits: 2048, Sensitive: true,
	})
	sess.Close()
	p11client.Close()

	ts, st := newCentral(t)

	// Enrollment with the wrong shared token must fail.
	if _, err := agent.Enroll(nil, ts.URL, "edge-01", "wrong"); err == nil {
		t.Fatal("enrollment with a wrong token must fail")
	}
	token, err := agent.Enroll(nil, ts.URL, "edge-01", enrollToken)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	cfg, err := policy.Load(rules.Default)
	if err != nil {
		t.Fatal(err)
	}
	reports, err := agent.CollectReports(testutil.ModulePath(t), testutil.UserPIN, &slot, cfg, "test")
	if err != nil {
		t.Fatalf("CollectReports: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("want 1 report, got %d", len(reports))
	}

	client := &agent.Client{ServerURL: ts.URL, Token: token}
	if err := client.Push(reports[0]); err != nil {
		t.Fatalf("Push: %v", err)
	}

	// A bad bearer token must be rejected.
	bad := &agent.Client{ServerURL: ts.URL, Token: "bogus"}
	if err := bad.Push(reports[0]); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("push with bad token should return 401, got %v", err)
	}

	// The fleet must now list the HSM under the agent's name.
	hsms, err := st.ListHSMs()
	if err != nil {
		t.Fatalf("ListHSMs: %v", err)
	}
	if len(hsms) != 1 || hsms[0].Source != "edge-01" {
		t.Fatalf("fleet listing wrong: %+v", hsms)
	}
	if hsms[0].LatestScore == nil {
		t.Fatal("fleet listing missing latest score")
	}

	// Mutate the token, push again: the server must record drift.
	mod, err := p11.Open(testutil.ModulePath(t))
	if err != nil {
		t.Fatalf("reopening module: %v", err)
	}
	sess2, err := mod.OpenSession(slot, testutil.UserPIN, true)
	if err != nil {
		mod.Close()
		t.Fatalf("reopening session: %v", err)
	}
	testutil.GenerateECKeyPair(t, sess2, "drift-key", []byte{0x02})
	sess2.Close()
	mod.Close()

	reports2, err := agent.CollectReports(testutil.ModulePath(t), testutil.UserPIN, &slot, cfg, "test")
	if err != nil {
		t.Fatalf("second CollectReports: %v", err)
	}
	if err := client.Push(reports2[0]); err != nil {
		t.Fatalf("second Push: %v", err)
	}

	events, err := st.ListDriftEvents(hsms[0].ID, 10)
	if err != nil {
		t.Fatalf("ListDriftEvents: %v", err)
	}
	if len(events) != 1 || events[0].Changes < 2 {
		t.Errorf("expected drift event for the new key pair: %+v", events)
	}

	// Agent bookkeeping: enrolled and touched.
	agents, err := st.ListAgents()
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents) != 1 || agents[0].Name != "edge-01" {
		t.Errorf("agent not registered: %+v", agents)
	}
}

func TestCentralModeRejectsLocalScans(t *testing.T) {
	ts, _ := newCentral(t)
	resp, err := http.Get(ts.URL + "/api/v1/slots/0/scan")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("central mode local scan: want 503, got %d", resp.StatusCode)
	}
	// Give the metric collectors a moment; then /metrics must still serve.
	time.Sleep(10 * time.Millisecond)
	mresp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer mresp.Body.Close()
	if mresp.StatusCode != http.StatusOK {
		t.Errorf("/metrics in central mode: want 200, got %d", mresp.StatusCode)
	}
}
