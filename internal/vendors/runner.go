package vendor

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Runner executes vendor tooling. Providers depend on this interface so
// tests can substitute canned outputs for real appliances.
type Runner interface {
	// Run executes a command and returns its combined standard output.
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// ExecRunner runs commands locally with a bounded timeout.
type ExecRunner struct {
	Timeout time.Duration
}

func (r ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return string(out), nil
}
