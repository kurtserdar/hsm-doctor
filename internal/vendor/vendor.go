// Package vendor extends HSM Doctor beyond PKCS#11: compiled-in providers
// collect appliance-level health (device, HA, partitions, tamper, backup)
// through vendor tooling and turn problems into scored findings.
//
// Providers register themselves at init time, mirroring how test profiles
// and policy packs work. The Provider interface is deliberately transport
// agnostic so an external-process adapter can join the registry later.
package vendor

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"gopkg.in/yaml.v3"
)

// Config carries one provider's settings from the vendor configuration
// file (addresses, usernames, file paths...). Never log values: they may
// reference credentials.
type Config map[string]string

// File is the parsed --vendor-config document.
type File struct {
	Providers map[string]Config `yaml:"providers"`
}

// LoadConfigFile reads and parses a vendor configuration file.
func LoadConfigFile(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading vendor config: %w", err)
	}
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing vendor config: %w", err)
	}
	return &f, nil
}

// For returns the configuration section for a provider; nil config is
// valid for providers that work without settings.
func (f *File) For(provider string) Config {
	if f == nil {
		return nil
	}
	return f.Providers[provider]
}

// DeviceHealth is appliance-level resource state. Pointers: nil means the
// provider could not determine the value.
type DeviceHealth struct {
	CPUPercent    *float64 `json:"cpu_percent,omitempty"`
	MemoryPercent *float64 `json:"memory_percent,omitempty"`
	DiskPercent   *float64 `json:"disk_percent,omitempty"`
	TemperatureC  *float64 `json:"temperature_c,omitempty"`
	PowerSupplyOK *bool    `json:"power_supply_ok,omitempty"`
	FansOK        *bool    `json:"fans_ok,omitempty"`
}

// HAMember is one node of a high-availability group.
type HAMember struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Up     bool   `json:"up"`
}

// HAStatus describes cluster/HA health.
type HAStatus struct {
	Group   string     `json:"group,omitempty"`
	InSync  *bool      `json:"in_sync,omitempty"`
	Members []HAMember `json:"members,omitempty"`
}

// PartitionInfo describes utilization of one partition/slot.
type PartitionInfo struct {
	Label            string `json:"label"`
	UsedObjects      *int   `json:"used_objects,omitempty"`
	MaxObjects       *int   `json:"max_objects,omitempty"`
	UsedStorageBytes *int64 `json:"used_storage_bytes,omitempty"`
	MaxStorageBytes  *int64 `json:"max_storage_bytes,omitempty"`
}

// TamperStatus reports physical/logical tamper state.
type TamperStatus struct {
	Tampered bool   `json:"tampered"`
	Detail   string `json:"detail,omitempty"`
}

// BackupStatus reports the last known backup.
type BackupStatus struct {
	LastBackup *time.Time `json:"last_backup,omitempty"`
	Detail     string     `json:"detail,omitempty"`
}

// Info is everything a provider learned about the device behind a token.
type Info struct {
	Provider string `json:"provider"`
	// Experimental marks providers that have not been validated against
	// real hardware; their output deserves scrutiny.
	Experimental bool              `json:"experimental,omitempty"`
	Device       *DeviceHealth     `json:"device,omitempty"`
	HA           *HAStatus         `json:"ha,omitempty"`
	Partitions   []PartitionInfo   `json:"partitions,omitempty"`
	Tamper       *TamperStatus     `json:"tamper,omitempty"`
	Backup       *BackupStatus     `json:"backup,omitempty"`
	Extra        map[string]string `json:"extra,omitempty"`
	// Findings feed the same scoring pipeline as PKCS#11 posture rules.
	Findings []policy.Finding `json:"findings,omitempty"`
}

// Provider is one vendor integration.
type Provider interface {
	// Name is the registry key used in the vendor configuration file.
	Name() string
	// Detect reports whether this provider recognizes the module/token
	// (typically by manufacturer or model strings).
	Detect(module p11.ModuleInfo, token *p11.TokenInfo) bool
	// Collect gathers vendor information. cfg may be nil for providers
	// that need no settings; providers requiring configuration return
	// ErrNotConfigured so callers can skip them gracefully.
	Collect(ctx context.Context, cfg Config) (*Info, error)
}

// ErrNotConfigured is returned by Collect when the provider needs settings
// that the vendor configuration file does not supply.
var ErrNotConfigured = fmt.Errorf("provider requires configuration (see --vendor-config)")

var registry = map[string]Provider{}

// Register adds a provider; called from provider package init functions.
func Register(p Provider) {
	if _, exists := registry[p.Name()]; exists {
		panic("duplicate vendor provider: " + p.Name())
	}
	registry[p.Name()] = p
}

// Detect returns the first registered provider recognizing the module and
// token, or nil.
func Detect(module p11.ModuleInfo, token *p11.TokenInfo) Provider {
	for _, name := range Names() {
		if registry[name].Detect(module, token) {
			return registry[name]
		}
	}
	return nil
}

// Get returns a provider by name.
func Get(name string) (Provider, bool) {
	p, ok := registry[name]
	return p, ok
}

// Names lists registered providers sorted by name.
func Names() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
