package luna

import (
	"fmt"
	"os"

	"github.com/kurtserdar/hsm-doctor/internal/vendors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// hostKeyCallback builds the SSH host-key verifier from config:
//   - known_hosts: verify against the given known_hosts file (recommended),
//   - insecure_ignore_host_key: "true" to skip verification (labs only).
func hostKeyCallback(cfg vendor.Config) (ssh.HostKeyCallback, error) {
	if cfg["insecure_ignore_host_key"] == "true" {
		//nolint:gosec // Operator explicitly opted out for a lab appliance.
		return ssh.InsecureIgnoreHostKey(), nil
	}
	kh := cfg["known_hosts"]
	if kh == "" {
		return nil, fmt.Errorf("luna: set known_hosts (or insecure_ignore_host_key: true for labs)")
	}
	if _, err := os.Stat(kh); err != nil {
		return nil, fmt.Errorf("luna: known_hosts %q: %w", kh, err)
	}
	cb, err := knownhosts.New(kh)
	if err != nil {
		return nil, fmt.Errorf("luna: parsing known_hosts: %w", err)
	}
	return cb, nil
}

func loadKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("luna: reading key file: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("luna: parsing key file: %w", err)
	}
	return signer, nil
}
