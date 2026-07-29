package vendor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
)

type stubProvider struct {
	name   string
	detect bool
}

func (s stubProvider) Name() string { return s.name }
func (s stubProvider) Detect(p11.ModuleInfo, *p11.TokenInfo) bool {
	return s.detect
}
func (s stubProvider) Collect(context.Context, Config) (*Info, error) {
	return &Info{Provider: s.name}, nil
}

func TestLoadConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vendor.yaml")
	content := `providers:
  luna:
    host: hsm1.example.com
    user: admin
  softhsm:
    conf: /etc/softhsm/softhsm2.conf
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if f.For("luna")["host"] != "hsm1.example.com" {
		t.Errorf("luna config wrong: %+v", f.For("luna"))
	}
	if f.For("softhsm")["conf"] != "/etc/softhsm/softhsm2.conf" {
		t.Errorf("softhsm config wrong: %+v", f.For("softhsm"))
	}
	if f.For("missing") != nil {
		t.Error("unknown provider should yield nil config")
	}
	// Nil-safe access.
	var nilFile *File
	if nilFile.For("anything") != nil {
		t.Error("nil file should yield nil config")
	}
}

func TestRegistryDetectPrefersRegisteredOrder(t *testing.T) {
	// Work on a private registry copy to avoid touching the global one.
	saved := registry
	registry = map[string]Provider{}
	defer func() { registry = saved }()

	Register(stubProvider{name: "zeta", detect: true})
	Register(stubProvider{name: "alpha", detect: true})

	// Detect iterates names sorted, so "alpha" wins over "zeta".
	p := Detect(p11.ModuleInfo{}, nil)
	if p == nil || p.Name() != "alpha" {
		t.Errorf("Detect should return the first sorted match, got %v", p)
	}

	Register(stubProvider{name: "beta", detect: false})
	if _, ok := Get("beta"); !ok {
		t.Error("Get should find a registered provider")
	}
	if len(Names()) != 3 {
		t.Errorf("Names should list all three: %v", Names())
	}
}

func TestRegisterRejectsDuplicates(t *testing.T) {
	saved := registry
	registry = map[string]Provider{}
	defer func() { registry = saved }()

	Register(stubProvider{name: "dup"})
	defer func() {
		if recover() == nil {
			t.Error("registering a duplicate provider should panic")
		}
	}()
	Register(stubProvider{name: "dup"})
}
