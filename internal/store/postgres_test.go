package store

import (
	"database/sql"
	"os"
	"testing"
)

// The PostgreSQL backend runs the same conformance suite when a test DSN is
// available (HSMDOCTOR_TEST_POSTGRES), e.g. in CI with a postgres service.
func TestPostgresConformance(t *testing.T) {
	dsn := os.Getenv("HSMDOCTOR_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("HSMDOCTOR_TEST_POSTGRES not set; skipping PostgreSQL conformance")
	}

	runConformance(t, func(t *testing.T) (Store, func() Store) {
		dropAllTables(t, dsn)
		open := func() Store {
			db, err := openPostgres(dsn)
			if err != nil {
				t.Fatalf("openPostgres: %v", err)
			}
			return db
		}
		s := open()
		t.Cleanup(func() { _ = s.Close() })
		return s, open
	})
}

// dropAllTables gives each conformance subtest a clean schema.
func dropAllTables(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("connecting to reset schema: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DROP TABLE IF EXISTS notifications, regression_events, drift_events, scans, agents, hsms, schema_version CASCADE`); err != nil {
		t.Fatalf("dropping tables: %v", err)
	}
}
