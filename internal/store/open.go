package store

import "strings"

// Open connects to the store described by dsn and applies pending
// migrations. A "postgres://" or "postgresql://" DSN selects the PostgreSQL
// backend; any other value is treated as a SQLite database file path.
func Open(dsn string) (Store, error) {
	if isPostgresDSN(dsn) {
		return openPostgres(dsn)
	}
	return openSQLite(dsn)
}

// isPostgresDSN reports whether dsn addresses a PostgreSQL server.
func isPostgresDSN(dsn string) bool {
	return strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")
}
