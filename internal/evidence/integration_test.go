//go:build integration

package evidence_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/evidence"
	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/testutil"
	"github.com/kurtserdar/hsm-doctor/rules"
)

func TestEvidenceAgainstSoftHSM(t *testing.T) {
	client, slot := testutil.NewSoftHSM(t)

	sess, err := client.OpenSession(slot, testutil.UserPIN, true)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	// A weak, extractable key so at least one FIPS control fails.
	testutil.GenerateRSAKeyPair(t, sess, testutil.KeyPairOpts{Label: "weak", ID: []byte{0x01}, Bits: 1024, Extractable: true})
	sess.Close()

	inv, err := inventory.Collect(client, slot, testutil.UserPIN)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	data, ok := rules.PackData("fips-140-3")
	if !ok {
		t.Fatal("fips-140-3 pack missing")
	}
	cfg, err := policy.Load(data)
	if err != nil {
		t.Fatalf("Load fips pack: %v", err)
	}

	rep := evidence.Build("test", inv, []evidence.LoadedPack{{Name: "fips-140-3", Config: cfg}}, time.Now())
	if len(rep.Packs) != 1 || len(rep.Packs[0].Controls) == 0 {
		t.Fatal("no controls produced")
	}
	if rep.Packs[0].Failed == 0 {
		t.Error("a weak extractable key must fail at least one FIPS control")
	}

	var h bytes.Buffer
	if err := rep.HTML(&h); err != nil {
		t.Fatalf("HTML: %v", err)
	}
}
