// Package snapshot records the state of a token as JSON and computes the
// drift between two recorded states.
package snapshot

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
)

// Snapshot is the on-disk format: a versioned wrapper around an inventory.
type Snapshot struct {
	Tool      string               `json:"tool"`
	Version   string               `json:"version"`
	Inventory *inventory.Inventory `json:"inventory"`
}

// New wraps an inventory in the snapshot envelope.
func New(version string, inv *inventory.Inventory) *Snapshot {
	return &Snapshot{Tool: "hsmdoctor", Version: version, Inventory: inv}
}

// Write serializes the snapshot as indented JSON.
func (s *Snapshot) Write(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

// LoadFile reads and validates a snapshot file.
func LoadFile(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading snapshot: %w", err)
	}
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing snapshot %s: %w", path, err)
	}
	if s.Inventory == nil {
		return nil, fmt.Errorf("snapshot %s contains no inventory (is it a scan report instead?)", path)
	}
	return &s, nil
}
