// Package store persists HSMs, scan history and drift events. The default
// implementation uses SQLite via the pure-Go modernc.org/sqlite driver, so
// no additional C dependencies enter the build.
package store

import (
	"encoding/json"
	"time"
)

// HSM is a token identified across scans by its serial number and source.
// Label, model and firmware hold the most recently observed values; changes
// to them show up as drift events, not as new HSM rows.
type HSM struct {
	ID           int64  `json:"id"`
	Serial       string `json:"serial"`
	Label        string `json:"label"`
	Model        string `json:"model"`
	Manufacturer string `json:"manufacturer"`
	Firmware     string `json:"firmware"`
	ModulePath   string `json:"module_path"`
	SlotID       uint   `json:"slot_id"`
	// Source is "local" for scans made by this process or the agent name
	// for pushed reports.
	Source    string    `json:"source"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// HSMSummary is an HSM with its latest scan result for fleet listings.
type HSMSummary struct {
	HSM
	LatestScore  *int       `json:"latest_score,omitempty"`
	LatestScanAt *time.Time `json:"latest_scan_at,omitempty"`
	LatestScanID *int64     `json:"latest_scan_id,omitempty"`
}

// ScanRecord is one stored scan: queryable columns plus the full report.
type ScanRecord struct {
	ID           int64           `json:"id"`
	HSMID        int64           `json:"hsm_id"`
	TakenAt      time.Time       `json:"taken_at"`
	Score        int             `json:"score"`
	Critical     int             `json:"critical"`
	High         int             `json:"high"`
	Medium       int             `json:"medium"`
	Low          int             `json:"low"`
	PrivateKeys  int             `json:"private_keys"`
	PublicKeys   int             `json:"public_keys"`
	SecretKeys   int             `json:"secret_keys"`
	Certificates int             `json:"certificates"`
	Report       json.RawMessage `json:"report,omitempty"`
}

// Summary returns the record without the report blob.
func (r ScanRecord) Summary() ScanRecord {
	r.Report = nil
	return r
}

// DriftEvent records the automatic diff between two consecutive scans.
type DriftEvent struct {
	ID         int64           `json:"id"`
	HSMID      int64           `json:"hsm_id"`
	DetectedAt time.Time       `json:"detected_at"`
	OldScanID  int64           `json:"old_scan_id"`
	NewScanID  int64           `json:"new_scan_id"`
	Changes    int             `json:"changes"`
	Diff       json.RawMessage `json:"diff"`
}

// Agent is an enrolled push client. Only the SHA-256 hash of its bearer
// token is stored.
type Agent struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	TokenHash string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
}

// Store is the persistence interface. A SQLite implementation ships today;
// the interface keeps the door open for PostgreSQL in a later release.
type Store interface {
	// UpsertHSM inserts or refreshes an HSM identified by (serial, source)
	// and returns its row ID.
	UpsertHSM(h *HSM) (int64, error)
	ListHSMs() ([]HSMSummary, error)
	GetHSM(id int64) (*HSM, error)

	InsertScan(rec *ScanRecord) (int64, error)
	// ListScans returns newest-first summaries without report blobs.
	ListScans(hsmID int64, limit int) ([]ScanRecord, error)
	GetScan(hsmID, scanID int64) (*ScanRecord, error)
	// LatestScan returns the most recent scan with its report blob, or nil.
	LatestScan(hsmID int64) (*ScanRecord, error)

	InsertDriftEvent(e *DriftEvent) (int64, error)
	ListDriftEvents(hsmID int64, limit int) ([]DriftEvent, error)

	// MarkNotified records that a notification for (hsmID, kind, ref,
	// threshold) has been sent. It returns true when this is the first time
	// (so the caller should send) and false when it was already recorded
	// (deduplicated). Used to email each certificate/threshold once.
	MarkNotified(hsmID int64, kind, ref string, threshold int) (bool, error)

	// UpsertAgent registers an agent or rotates its token hash on re-enroll.
	UpsertAgent(name, tokenHash string) (int64, error)
	// GetAgentByTokenHash resolves a pushed bearer token; nil when unknown.
	GetAgentByTokenHash(hash string) (*Agent, error)
	TouchAgent(id int64) error
	ListAgents() ([]Agent, error)

	Close() error
}
