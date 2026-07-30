package store

import (
	"net/url"
	"strings"
)

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

// Redact hides the password in a PostgreSQL DSN so it is safe to log. SQLite
// paths are returned unchanged. Both userinfo passwords
// (postgres://user:pw@host) and query-string passwords
// (postgres://user@host?password=pw) are masked.
func Redact(dsn string) string {
	if !isPostgresDSN(dsn) {
		return dsn
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return "postgres://[unparseable DSN]"
	}
	if u.User != nil {
		if _, hasPw := u.User.Password(); hasPw {
			u.User = url.UserPassword(u.User.Username(), "****")
		}
	}
	q := u.Query()
	for _, key := range []string{"password", "sslpassword"} {
		if q.Has(key) {
			q.Set(key, "****")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}
