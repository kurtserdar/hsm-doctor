//go:build integration

package policy_test

import (
	"testing"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/testutil"
	"github.com/kurtserdar/hsm-doctor/rules"
)

// The strict pack must flag a deliberately sloppy key on a real token.
func TestStrictPackAgainstSoftHSM(t *testing.T) {
	client, slot := testutil.NewSoftHSM(t)

	sess, err := client.OpenSession(slot, testutil.UserPIN, true)
	if err != nil {
		t.Fatalf("opening session: %v", err)
	}
	testutil.GenerateRSAKeyPair(t, sess, testutil.KeyPairOpts{
		Label: "sloppy-key", ID: []byte{0x01}, Bits: 2048,
		Extractable: true, Sensitive: false,
	})
	sess.Close()

	inv, err := inventory.Collect(client, slot, testutil.UserPIN)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	data, ok := rules.PackData("strict")
	if !ok {
		t.Fatal("strict pack missing")
	}
	cfg, err := policy.Load(data)
	if err != nil {
		t.Fatalf("loading strict pack: %v", err)
	}

	res := policy.Evaluate(inv, cfg, time.Now())
	fired := map[string]bool{}
	for _, f := range res.Findings {
		fired[f.RuleID] = true
	}
	// STRICT-001 non-sensitive, STRICT-002 extractable, STRICT-004
	// never_extractable=false and STRICT-006 sign+decrypt must all fire on
	// the sloppy key; STRICT-011 orphan (no cert/pubkey pair? public key
	// exists with same ID, so no orphan).
	for _, want := range []string{"STRICT-001", "STRICT-002", "STRICT-004", "STRICT-006"} {
		if !fired[want] {
			t.Errorf("strict pack should fire %s on the sloppy key; got %+v", want, res.Findings)
		}
	}
	// Two criticals alone cost 50 points; the mediums push further down.
	if res.Score > 50 {
		t.Errorf("score should be heavily reduced for the sloppy key, got %d", res.Score)
	}
}
