package cli

import (
	"os"

	"github.com/kurtserdar/hsm-doctor/internal/store"
)

// resolveDBPath resolves the database DSN/path from the --db flag, falling
// back to the HSMDOCTOR_DB environment variable (so a password-bearing
// PostgreSQL DSN can stay out of the process list) and finally to the
// default SQLite path.
func resolveDBPath(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if env := os.Getenv("HSMDOCTOR_DB"); env != "" {
		return env, nil
	}
	return store.DefaultPath()
}
