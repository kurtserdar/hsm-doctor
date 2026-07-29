//go:build integration

package bench_test

import (
	"testing"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/bench"
	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/testutil"
)

func TestBenchAgainstSoftHSM(t *testing.T) {
	client, slot := testutil.NewSoftHSM(t)

	opts := bench.Options{
		Duration: 300 * time.Millisecond,
		MaxOps:   200,
		Sessions: 2,
	}
	res, err := bench.Run(client, slot, testutil.UserPIN, opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Measurements) != 3 {
		t.Fatalf("want 3 measurements, got %d", len(res.Measurements))
	}

	for _, m := range res.Measurements {
		if !m.Supported {
			t.Errorf("%s should be supported by SoftHSM: %s", m.Name, m.Error)
			continue
		}
		if m.Error != "" {
			t.Errorf("%s failed: %s", m.Name, m.Error)
		}
		if m.Ops <= 0 || m.OpsPerSec <= 0 {
			t.Errorf("%s produced no throughput: %+v", m.Name, m)
		}
		// The absolute op budget must be respected.
		if m.Ops > int64(opts.MaxOps) {
			t.Errorf("%s exceeded op budget: %d > %d", m.Name, m.Ops, opts.MaxOps)
		}
	}

	// Benchmarks must leave no objects behind.
	inv, err := inventory.Collect(client, slot, testutil.UserPIN)
	if err != nil {
		t.Fatalf("Collect after bench: %v", err)
	}
	if len(inv.Objects) != 0 {
		t.Errorf("benchmark left %d object(s) on the token", len(inv.Objects))
	}
}
