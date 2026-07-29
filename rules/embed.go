// Package rules embeds the default security posture rule set so the binary
// works out of the box without external files.
package rules

import _ "embed"

// Default is the built-in rules file (default.yaml).
//
//go:embed default.yaml
var Default []byte
