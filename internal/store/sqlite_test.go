package store

import (
	"path/filepath"
	"testing"
)

// The SQLite backend runs the full conformance suite on every test run.
func TestSQLiteConformance(t *testing.T) {
	runConformance(t, func(t *testing.T) (Store, func() Store) {
		path := filepath.Join(t.TempDir(), "conformance.db")
		open := func() Store {
			db, err := Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			return db
		}
		s := open()
		t.Cleanup(func() { _ = s.Close() })
		return s, open
	})
}
