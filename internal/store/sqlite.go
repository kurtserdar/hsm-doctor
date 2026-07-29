package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// migrations are applied in order; PRAGMA user_version tracks progress.
var migrations = []string{
	`
CREATE TABLE hsms (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    serial        TEXT NOT NULL,
    label         TEXT NOT NULL DEFAULT '',
    model         TEXT NOT NULL DEFAULT '',
    manufacturer  TEXT NOT NULL DEFAULT '',
    firmware      TEXT NOT NULL DEFAULT '',
    module_path   TEXT NOT NULL DEFAULT '',
    slot_id       INTEGER NOT NULL DEFAULT 0,
    source        TEXT NOT NULL DEFAULT 'local',
    first_seen    TIMESTAMP NOT NULL,
    last_seen     TIMESTAMP NOT NULL,
    UNIQUE (serial, source)
);

CREATE TABLE scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hsm_id        INTEGER NOT NULL REFERENCES hsms(id) ON DELETE CASCADE,
    taken_at      TIMESTAMP NOT NULL,
    score         INTEGER NOT NULL,
    critical      INTEGER NOT NULL DEFAULT 0,
    high          INTEGER NOT NULL DEFAULT 0,
    medium        INTEGER NOT NULL DEFAULT 0,
    low           INTEGER NOT NULL DEFAULT 0,
    private_keys  INTEGER NOT NULL DEFAULT 0,
    public_keys   INTEGER NOT NULL DEFAULT 0,
    secret_keys   INTEGER NOT NULL DEFAULT 0,
    certificates  INTEGER NOT NULL DEFAULT 0,
    report        BLOB NOT NULL
);
CREATE INDEX idx_scans_hsm_taken ON scans(hsm_id, taken_at DESC, id DESC);

CREATE TABLE drift_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hsm_id        INTEGER NOT NULL REFERENCES hsms(id) ON DELETE CASCADE,
    detected_at   TIMESTAMP NOT NULL,
    old_scan_id   INTEGER NOT NULL,
    new_scan_id   INTEGER NOT NULL,
    changes       INTEGER NOT NULL,
    diff          BLOB NOT NULL
);
CREATE INDEX idx_drift_hsm ON drift_events(hsm_id, detected_at DESC, id DESC);
`,
}

// DB is the SQLite-backed Store.
type DB struct {
	db *sql.DB
}

var _ Store = (*DB)(nil)

// DefaultPath returns the default database location following the XDG
// convention, creating parent directories as needed.
func DefaultPath() (string, error) {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolving home directory: %w", err)
		}
		base = filepath.Join(home, ".local", "share")
	}
	dir := filepath.Join(base, "hsmdoctor")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating data directory: %w", err)
	}
	return filepath.Join(dir, "hsmdoctor.db"), nil
}

// Open opens (creating if necessary) the SQLite database at path and applies
// pending migrations.
func Open(path string) (*DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)",
		url.PathEscape(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	// SQLite handles one writer at a time; a single connection avoids
	// SQLITE_BUSY surprises under concurrent API calls.
	db.SetMaxOpenConns(1)

	s := &DB{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *DB) migrate() error {
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("reading schema version: %w", err)
	}
	for i := version; i < len(migrations); i++ {
		if _, err := s.db.Exec(migrations[i]); err != nil {
			return fmt.Errorf("applying migration %d: %w", i+1, err)
		}
		if _, err := s.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			return fmt.Errorf("updating schema version: %w", err)
		}
	}
	return nil
}

// Close closes the database.
func (s *DB) Close() error {
	return s.db.Close()
}

func (s *DB) UpsertHSM(h *HSM) (int64, error) {
	now := time.Now().UTC()
	var id int64
	err := s.db.QueryRow(`
INSERT INTO hsms (serial, label, model, manufacturer, firmware, module_path, slot_id, source, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (serial, source) DO UPDATE SET
    label = excluded.label,
    model = excluded.model,
    manufacturer = excluded.manufacturer,
    firmware = excluded.firmware,
    module_path = excluded.module_path,
    slot_id = excluded.slot_id,
    last_seen = excluded.last_seen
RETURNING id`,
		h.Serial, h.Label, h.Model, h.Manufacturer, h.Firmware,
		h.ModulePath, h.SlotID, h.Source, now, now).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("upserting HSM: %w", err)
	}
	return id, nil
}

func (s *DB) ListHSMs() ([]HSMSummary, error) {
	rows, err := s.db.Query(`
SELECT h.id, h.serial, h.label, h.model, h.manufacturer, h.firmware,
       h.module_path, h.slot_id, h.source, h.first_seen, h.last_seen,
       s.id, s.score, s.taken_at
FROM hsms h
LEFT JOIN scans s ON s.id = (
    SELECT id FROM scans WHERE hsm_id = h.id ORDER BY taken_at DESC, id DESC LIMIT 1
)
ORDER BY h.label, h.serial`)
	if err != nil {
		return nil, fmt.Errorf("listing HSMs: %w", err)
	}
	defer rows.Close()

	var out []HSMSummary
	for rows.Next() {
		var h HSMSummary
		var scanID sql.NullInt64
		var score sql.NullInt64
		var takenAt sql.NullTime
		if err := rows.Scan(&h.ID, &h.Serial, &h.Label, &h.Model, &h.Manufacturer, &h.Firmware,
			&h.ModulePath, &h.SlotID, &h.Source, &h.FirstSeen, &h.LastSeen,
			&scanID, &score, &takenAt); err != nil {
			return nil, err
		}
		if scanID.Valid {
			id := scanID.Int64
			sc := int(score.Int64)
			at := takenAt.Time
			h.LatestScanID, h.LatestScore, h.LatestScanAt = &id, &sc, &at
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *DB) GetHSM(id int64) (*HSM, error) {
	var h HSM
	err := s.db.QueryRow(`
SELECT id, serial, label, model, manufacturer, firmware, module_path, slot_id, source, first_seen, last_seen
FROM hsms WHERE id = ?`, id).Scan(
		&h.ID, &h.Serial, &h.Label, &h.Model, &h.Manufacturer, &h.Firmware,
		&h.ModulePath, &h.SlotID, &h.Source, &h.FirstSeen, &h.LastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("loading HSM %d: %w", id, err)
	}
	return &h, nil
}

func (s *DB) InsertScan(rec *ScanRecord) (int64, error) {
	res, err := s.db.Exec(`
INSERT INTO scans (hsm_id, taken_at, score, critical, high, medium, low,
                   private_keys, public_keys, secret_keys, certificates, report)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.HSMID, rec.TakenAt.UTC(), rec.Score, rec.Critical, rec.High, rec.Medium, rec.Low,
		rec.PrivateKeys, rec.PublicKeys, rec.SecretKeys, rec.Certificates, []byte(rec.Report))
	if err != nil {
		return 0, fmt.Errorf("inserting scan: %w", err)
	}
	return res.LastInsertId()
}

const scanSummaryCols = `id, hsm_id, taken_at, score, critical, high, medium, low,
       private_keys, public_keys, secret_keys, certificates`

func scanSummaryRow(scanner interface{ Scan(...any) error }, rec *ScanRecord) error {
	return scanner.Scan(&rec.ID, &rec.HSMID, &rec.TakenAt, &rec.Score,
		&rec.Critical, &rec.High, &rec.Medium, &rec.Low,
		&rec.PrivateKeys, &rec.PublicKeys, &rec.SecretKeys, &rec.Certificates)
}

func (s *DB) ListScans(hsmID int64, limit int) ([]ScanRecord, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.Query(`
SELECT `+scanSummaryCols+` FROM scans
WHERE hsm_id = ? ORDER BY taken_at DESC, id DESC LIMIT ?`, hsmID, limit)
	if err != nil {
		return nil, fmt.Errorf("listing scans: %w", err)
	}
	defer rows.Close()

	var out []ScanRecord
	for rows.Next() {
		var rec ScanRecord
		if err := scanSummaryRow(rows, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *DB) GetScan(hsmID, scanID int64) (*ScanRecord, error) {
	var rec ScanRecord
	var report []byte
	err := s.db.QueryRow(`
SELECT `+scanSummaryCols+`, report FROM scans WHERE id = ? AND hsm_id = ?`, scanID, hsmID).
		Scan(&rec.ID, &rec.HSMID, &rec.TakenAt, &rec.Score,
			&rec.Critical, &rec.High, &rec.Medium, &rec.Low,
			&rec.PrivateKeys, &rec.PublicKeys, &rec.SecretKeys, &rec.Certificates, &report)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("loading scan %d: %w", scanID, err)
	}
	rec.Report = report
	return &rec, nil
}

func (s *DB) LatestScan(hsmID int64) (*ScanRecord, error) {
	var rec ScanRecord
	var report []byte
	err := s.db.QueryRow(`
SELECT `+scanSummaryCols+`, report FROM scans
WHERE hsm_id = ? ORDER BY taken_at DESC, id DESC LIMIT 1`, hsmID).
		Scan(&rec.ID, &rec.HSMID, &rec.TakenAt, &rec.Score,
			&rec.Critical, &rec.High, &rec.Medium, &rec.Low,
			&rec.PrivateKeys, &rec.PublicKeys, &rec.SecretKeys, &rec.Certificates, &report)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("loading latest scan: %w", err)
	}
	rec.Report = report
	return &rec, nil
}

func (s *DB) InsertDriftEvent(e *DriftEvent) (int64, error) {
	res, err := s.db.Exec(`
INSERT INTO drift_events (hsm_id, detected_at, old_scan_id, new_scan_id, changes, diff)
VALUES (?, ?, ?, ?, ?, ?)`,
		e.HSMID, e.DetectedAt.UTC(), e.OldScanID, e.NewScanID, e.Changes, []byte(e.Diff))
	if err != nil {
		return 0, fmt.Errorf("inserting drift event: %w", err)
	}
	return res.LastInsertId()
}

func (s *DB) ListDriftEvents(hsmID int64, limit int) ([]DriftEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.Query(`
SELECT id, hsm_id, detected_at, old_scan_id, new_scan_id, changes, diff
FROM drift_events WHERE hsm_id = ? ORDER BY detected_at DESC, id DESC LIMIT ?`, hsmID, limit)
	if err != nil {
		return nil, fmt.Errorf("listing drift events: %w", err)
	}
	defer rows.Close()

	var out []DriftEvent
	for rows.Next() {
		var e DriftEvent
		var diff []byte
		if err := rows.Scan(&e.ID, &e.HSMID, &e.DetectedAt, &e.OldScanID, &e.NewScanID, &e.Changes, &diff); err != nil {
			return nil, err
		}
		e.Diff = diff
		out = append(out, e)
	}
	return out, rows.Err()
}
