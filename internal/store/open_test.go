package store

import "testing"

func TestIsPostgresDSN(t *testing.T) {
	cases := map[string]bool{
		"postgres://u:p@h/db":   true,
		"postgresql://u:p@h/db": true,
		"/var/lib/hsmdoctor.db": false,
		"hsmdoctor.db":          false,
		"file:test.db":          false,
	}
	for dsn, want := range cases {
		if got := isPostgresDSN(dsn); got != want {
			t.Errorf("isPostgresDSN(%q) = %v, want %v", dsn, got, want)
		}
	}
}

func TestRedact(t *testing.T) {
	got := Redact("postgres://hsmdoctor:secret@db.example.com:5432/hsmdoctor?sslmode=require")
	if got == "" || contains(got, "secret") {
		t.Errorf("password not redacted: %q", got)
	}
	if !contains(got, "hsmdoctor") || !contains(got, "db.example.com") {
		t.Errorf("redaction dropped non-secret parts: %q", got)
	}
	// SQLite paths pass through unchanged.
	if p := "/var/lib/hsmdoctor.db"; Redact(p) != p {
		t.Errorf("SQLite path should be unchanged: %q", Redact(p))
	}
	// A DSN with no password stays intact.
	if got := Redact("postgres://u@h/db"); contains(got, "****") {
		t.Errorf("no password should mean no redaction marker: %q", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
