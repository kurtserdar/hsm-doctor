package advisory

import _ "embed"

//go:embed advisories.yaml
var embedded []byte

// Default returns the built-in advisory feed.
func Default() (*Feed, error) {
	return Load(embedded)
}
