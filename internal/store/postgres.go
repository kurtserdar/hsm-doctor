package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver
)

// pgMigrations mirror the SQLite schema in PostgreSQL types (IDENTITY,
// BYTEA, TIMESTAMPTZ). The data model is identical; only the dialect
// differs.
var pgMigrations = []string{
	`
CREATE TABLE hsms (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    serial        TEXT NOT NULL,
    label         TEXT NOT NULL DEFAULT '',
    model         TEXT NOT NULL DEFAULT '',
    manufacturer  TEXT NOT NULL DEFAULT '',
    firmware      TEXT NOT NULL DEFAULT '',
    module_path   TEXT NOT NULL DEFAULT '',
    slot_id       BIGINT NOT NULL DEFAULT 0,
    source        TEXT NOT NULL DEFAULT 'local',
    first_seen    TIMESTAMPTZ NOT NULL,
    last_seen     TIMESTAMPTZ NOT NULL,
    UNIQUE (serial, source)
);

CREATE TABLE scans (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    hsm_id        BIGINT NOT NULL REFERENCES hsms(id) ON DELETE CASCADE,
    taken_at      TIMESTAMPTZ NOT NULL,
    score         INTEGER NOT NULL,
    critical      INTEGER NOT NULL DEFAULT 0,
    high          INTEGER NOT NULL DEFAULT 0,
    medium        INTEGER NOT NULL DEFAULT 0,
    low           INTEGER NOT NULL DEFAULT 0,
    private_keys  INTEGER NOT NULL DEFAULT 0,
    public_keys   INTEGER NOT NULL DEFAULT 0,
    secret_keys   INTEGER NOT NULL DEFAULT 0,
    certificates  INTEGER NOT NULL DEFAULT 0,
    report        BYTEA NOT NULL
);
CREATE INDEX idx_scans_hsm_taken ON scans(hsm_id, taken_at DESC, id DESC);

CREATE TABLE drift_events (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    hsm_id        BIGINT NOT NULL REFERENCES hsms(id) ON DELETE CASCADE,
    detected_at   TIMESTAMPTZ NOT NULL,
    old_scan_id   BIGINT NOT NULL,
    new_scan_id   BIGINT NOT NULL,
    changes       INTEGER NOT NULL,
    diff          BYTEA NOT NULL
);
CREATE INDEX idx_drift_hsm ON drift_events(hsm_id, detected_at DESC, id DESC);

CREATE TABLE agents (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    token_hash  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_agents_token ON agents(token_hash);

CREATE TABLE notifications (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    hsm_id      BIGINT NOT NULL,
    kind        TEXT NOT NULL,
    ref         TEXT NOT NULL,
    threshold   INTEGER NOT NULL,
    notified_at TIMESTAMPTZ NOT NULL,
    UNIQUE (hsm_id, kind, ref, threshold)
);
`,
}

// PG is the PostgreSQL-backed Store.
type PG struct {
	db *sql.DB
}

var _ Store = (*PG)(nil)

// openPostgres connects to the server at dsn and applies pending migrations.
func openPostgres(dsn string) (*PG, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetConnMaxIdleTime(5 * time.Minute)

	s := &PG{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// migrate applies pending migrations, tracking the applied version in a
// dedicated table (PostgreSQL has no PRAGMA user_version). The whole step
// runs under an advisory lock so concurrent servers cannot race the schema.
func (s *PG) migrate() error {
	if _, err := s.db.Exec(`SELECT pg_advisory_lock(4262766)`); err != nil {
		return fmt.Errorf("acquiring migration lock: %w", err)
	}
	defer func() { _, _ = s.db.Exec(`SELECT pg_advisory_unlock(4262766)`) }()

	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("creating schema_version: %w", err)
	}
	var version int
	err := s.db.QueryRow(`SELECT version FROM schema_version LIMIT 1`).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := s.db.Exec(`INSERT INTO schema_version (version) VALUES (0)`); err != nil {
			return fmt.Errorf("initializing schema_version: %w", err)
		}
		version = 0
	} else if err != nil {
		return fmt.Errorf("reading schema version: %w", err)
	}

	for i := version; i < len(pgMigrations); i++ {
		if _, err := s.db.Exec(pgMigrations[i]); err != nil {
			return fmt.Errorf("applying migration %d: %w", i+1, err)
		}
		if _, err := s.db.Exec(`UPDATE schema_version SET version = $1`, i+1); err != nil {
			return fmt.Errorf("updating schema version: %w", err)
		}
	}
	return nil
}

// Close closes the connection pool.
func (s *PG) Close() error { return s.db.Close() }

func (s *PG) UpsertHSM(h *HSM) (int64, error) {
	now := time.Now().UTC()
	var id int64
	err := s.db.QueryRow(`
INSERT INTO hsms (serial, label, model, manufacturer, firmware, module_path, slot_id, source, first_seen, last_seen)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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

func (s *PG) ListHSMs() ([]HSMSummary, error) {
	rows, err := s.db.Query(`
SELECT h.id, h.serial, h.label, h.model, h.manufacturer, h.firmware,
       h.module_path, h.slot_id, h.source, h.first_seen, h.last_seen,
       s.id, s.score, s.taken_at
FROM hsms h
LEFT JOIN LATERAL (
    SELECT id, score, taken_at FROM scans
    WHERE hsm_id = h.id ORDER BY taken_at DESC, id DESC LIMIT 1
) s ON true
ORDER BY h.label, h.serial`)
	if err != nil {
		return nil, fmt.Errorf("listing HSMs: %w", err)
	}
	defer rows.Close()

	var out []HSMSummary
	for rows.Next() {
		var h HSMSummary
		var scanID, score sql.NullInt64
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

func (s *PG) GetHSM(id int64) (*HSM, error) {
	var h HSM
	err := s.db.QueryRow(`
SELECT id, serial, label, model, manufacturer, firmware, module_path, slot_id, source, first_seen, last_seen
FROM hsms WHERE id = $1`, id).Scan(
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

func (s *PG) InsertScan(rec *ScanRecord) (int64, error) {
	var id int64
	err := s.db.QueryRow(`
INSERT INTO scans (hsm_id, taken_at, score, critical, high, medium, low,
                   private_keys, public_keys, secret_keys, certificates, report)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING id`,
		rec.HSMID, rec.TakenAt.UTC(), rec.Score, rec.Critical, rec.High, rec.Medium, rec.Low,
		rec.PrivateKeys, rec.PublicKeys, rec.SecretKeys, rec.Certificates, []byte(rec.Report)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("inserting scan: %w", err)
	}
	return id, nil
}

func (s *PG) ListScans(hsmID int64, limit int) ([]ScanRecord, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.Query(`
SELECT `+scanSummaryCols+` FROM scans
WHERE hsm_id = $1 ORDER BY taken_at DESC, id DESC LIMIT $2`, hsmID, limit)
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

func (s *PG) GetScan(hsmID, scanID int64) (*ScanRecord, error) {
	var rec ScanRecord
	var report []byte
	err := s.db.QueryRow(`
SELECT `+scanSummaryCols+`, report FROM scans WHERE id = $1 AND hsm_id = $2`, scanID, hsmID).
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

func (s *PG) LatestScan(hsmID int64) (*ScanRecord, error) {
	var rec ScanRecord
	var report []byte
	err := s.db.QueryRow(`
SELECT `+scanSummaryCols+`, report FROM scans
WHERE hsm_id = $1 ORDER BY taken_at DESC, id DESC LIMIT 1`, hsmID).
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

func (s *PG) UpsertAgent(name, tokenHash string) (int64, error) {
	now := time.Now().UTC()
	var id int64
	err := s.db.QueryRow(`
INSERT INTO agents (name, token_hash, created_at, last_seen)
VALUES ($1, $2, $3, $4)
ON CONFLICT (name) DO UPDATE SET token_hash = excluded.token_hash, last_seen = excluded.last_seen
RETURNING id`, name, tokenHash, now, now).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("upserting agent: %w", err)
	}
	return id, nil
}

func (s *PG) GetAgentByTokenHash(hash string) (*Agent, error) {
	var a Agent
	err := s.db.QueryRow(`
SELECT id, name, token_hash, created_at, last_seen FROM agents WHERE token_hash = $1`, hash).
		Scan(&a.ID, &a.Name, &a.TokenHash, &a.CreatedAt, &a.LastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("looking up agent: %w", err)
	}
	return &a, nil
}

func (s *PG) TouchAgent(id int64) error {
	_, err := s.db.Exec(`UPDATE agents SET last_seen = $1 WHERE id = $2`, time.Now().UTC(), id)
	return err
}

func (s *PG) ListAgents() ([]Agent, error) {
	rows, err := s.db.Query(`SELECT id, name, token_hash, created_at, last_seen FROM agents ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("listing agents: %w", err)
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(&a.ID, &a.Name, &a.TokenHash, &a.CreatedAt, &a.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *PG) MarkNotified(hsmID int64, kind, ref string, threshold int) (bool, error) {
	res, err := s.db.Exec(`
INSERT INTO notifications (hsm_id, kind, ref, threshold, notified_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (hsm_id, kind, ref, threshold) DO NOTHING`,
		hsmID, kind, ref, threshold, time.Now().UTC())
	if err != nil {
		return false, fmt.Errorf("recording notification: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *PG) InsertDriftEvent(e *DriftEvent) (int64, error) {
	var id int64
	err := s.db.QueryRow(`
INSERT INTO drift_events (hsm_id, detected_at, old_scan_id, new_scan_id, changes, diff)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id`,
		e.HSMID, e.DetectedAt.UTC(), e.OldScanID, e.NewScanID, e.Changes, []byte(e.Diff)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("inserting drift event: %w", err)
	}
	return id, nil
}

func (s *PG) ListDriftEvents(hsmID int64, limit int) ([]DriftEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.Query(`
SELECT id, hsm_id, detected_at, old_scan_id, new_scan_id, changes, diff
FROM drift_events WHERE hsm_id = $1 ORDER BY detected_at DESC, id DESC LIMIT $2`, hsmID, limit)
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
