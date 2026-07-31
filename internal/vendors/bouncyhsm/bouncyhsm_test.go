package bouncyhsm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/vendors"
)

func TestDetect(t *testing.T) {
	p := &provider{}
	if !p.Detect(p11.ModuleInfo{Manufacturer: "BouncyHsm"}, nil) {
		t.Error("should detect BouncyHsm by manufacturer")
	}
	if !p.Detect(p11.ModuleInfo{}, &p11.TokenInfo{Manufacturer: "BouncyHsm"}) {
		t.Error("should detect BouncyHsm by token manufacturer")
	}
	if p.Detect(p11.ModuleInfo{Manufacturer: "SoftHSM"}, nil) {
		t.Error("must not detect SoftHSM")
	}
}

// Response shapes mirror BouncyHsm's REST controllers (HsmInfoController,
// StatsController).
const versionsJSON = `{"version":"2.0.0","bouncyCastleVersion":"2.4.0","p11Versions":["2.40","3.1","3.2"],"commit":"abc1234"}`
const statsJSON = `{"connectedApplications":1,"roSessionCount":0,"rwSessionCount":2,"slotCount":3,"totalObjectCount":12,"privateKeys":4}`

// newServer builds a fake BouncyHsm REST API. A handler returning "" for a path
// means "respond 500" so failure paths can be exercised.
func newServer(t *testing.T, versions, stats string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/HsmInfo/Versions", func(w http.ResponseWriter, _ *http.Request) {
		if versions == "" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(versions))
	})
	mux.HandleFunc("/Stats", func(w http.ResponseWriter, _ *http.Request) {
		if stats == "" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(stats))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func hasFinding(info *vendor.Info, id string) bool {
	for _, f := range info.Findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestCollect(t *testing.T) {
	url := newServer(t, versionsJSON, statsJSON)
	p := &provider{}
	info, err := p.Collect(context.Background(), vendor.Config{"url": url})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !info.Experimental {
		t.Error("bouncyhsm provider must be marked experimental")
	}
	if info.Extra["version"] != "2.0.0" || info.Extra["pkcs11_versions"] != "2.40, 3.1, 3.2" {
		t.Errorf("version data not parsed: %+v", info.Extra)
	}
	if info.Extra["slots"] != "3" || info.Extra["objects"] != "12" || info.Extra["private_keys"] != "4" {
		t.Errorf("stats not parsed: %+v", info.Extra)
	}
	if !hasFinding(info, "BOUNCYHSM-001") {
		t.Error("a non-production simulator must always raise BOUNCYHSM-001")
	}
}

func TestNotConfigured(t *testing.T) {
	p := &provider{}
	if _, err := p.Collect(context.Background(), vendor.Config{}); err != vendor.ErrNotConfigured {
		t.Errorf("missing url should return ErrNotConfigured, got %v", err)
	}
}

// If the management API is unreachable, Collect reports an error.
func TestVersionsUnreachableReturnsError(t *testing.T) {
	url := newServer(t, "", statsJSON) // Versions → 500
	p := &provider{}
	if _, err := p.Collect(context.Background(), vendor.Config{"url": url}); err == nil {
		t.Fatal("expected an error when /HsmInfo/Versions fails")
	}
}

// A failing /Stats must not sink the version data or the warning.
func TestStatsBestEffort(t *testing.T) {
	url := newServer(t, versionsJSON, "") // Stats → 500
	p := &provider{}
	info, err := p.Collect(context.Background(), vendor.Config{"url": url})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if info.Extra["version"] != "2.0.0" {
		t.Errorf("version should survive a stats failure: %+v", info.Extra)
	}
	if _, ok := info.Extra["slots"]; ok {
		t.Error("no stats fields expected when /Stats fails")
	}
	if !hasFinding(info, "BOUNCYHSM-001") {
		t.Error("the non-production warning must still be present")
	}
}
