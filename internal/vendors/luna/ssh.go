package luna

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/vendors"
	"golang.org/x/crypto/ssh"
)

// atoiSafe parses an integer, tolerating surrounding punctuation.
func atoiSafe(s string) (int, error) {
	return strconv.Atoi(s)
}

// sshRunner runs lunash commands over SSH. lunash is a restricted shell, so
// each command is issued as a separate session.
type sshRunner struct {
	addr   string
	config *ssh.ClientConfig
}

func newSSHRunner(cfg vendor.Config) (vendor.Runner, error) {
	user := cfg["user"]
	if user == "" {
		user = "admin"
	}
	host := cfg["host"]
	port := cfg["port"]
	if port == "" {
		port = "22"
	}

	var auth []ssh.AuthMethod
	if pw := cfg["password"]; pw != "" {
		auth = append(auth, ssh.Password(pw))
	}
	if key := cfg["key_file"]; key != "" {
		signer, err := loadKey(key)
		if err != nil {
			return nil, err
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if len(auth) == 0 {
		return nil, fmt.Errorf("luna: no SSH credentials in config (set password or key_file)")
	}

	// Host key verification is required unless the operator explicitly opts
	// out; silently trusting keys would undermine the appliance's identity.
	hostKey, err := hostKeyCallback(cfg)
	if err != nil {
		return nil, err
	}

	return &sshRunner{
		addr: host + ":" + port,
		config: &ssh.ClientConfig{
			User:            user,
			Auth:            auth,
			HostKeyCallback: hostKey,
			Timeout:         15 * time.Second,
		},
	}, nil
}

func (r *sshRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	client, err := ssh.Dial("tcp", r.addr, r.config)
	if err != nil {
		return "", fmt.Errorf("connecting to %s: %w", r.addr, err)
	}
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer func() { _ = session.Close() }()

	cmd := name
	for _, a := range args {
		cmd += " " + a
	}
	out, err := session.CombinedOutput(cmd)
	return string(out), err
}
