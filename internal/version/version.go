// Package version holds build-time version information.
package version

// These variables are intended to be overridden at build time via
// -ldflags "-X github.com/kurtserdar/hsm-doctor/internal/version.Version=..."
var (
	// Version is the semantic version of the build.
	Version = "1.9.0"
	// Commit is the git commit hash the binary was built from.
	Commit = "unknown"
)
