// Package vendortest provides shared test helpers for vendor providers that
// collect data by running external commands through a vendors.Runner.
package vendortest

import "context"

// Runner is a fake vendors.Runner. It returns canned output per command name
// and can inject an error for a given command, so provider tests can exercise
// both happy paths and tool-missing / permission-denied failure paths. It also
// records the commands invoked, in order.
type Runner struct {
	// Outputs maps a command name to the stdout it should return.
	Outputs map[string]string
	// Errs maps a command name to an error it should return (output is then "").
	Errs map[string]error
	// Calls records every command name Run was invoked with, in order.
	Calls []string
}

// Run implements vendors.Runner.
func (r *Runner) Run(_ context.Context, name string, _ ...string) (string, error) {
	r.Calls = append(r.Calls, name)
	if r.Errs != nil {
		if err := r.Errs[name]; err != nil {
			return "", err
		}
	}
	if r.Outputs == nil {
		return "", nil
	}
	return r.Outputs[name], nil
}
