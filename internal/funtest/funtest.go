// Package funtest runs safe functional test profiles against a token.
//
// All objects created during a test are session objects (CKA_TOKEN=false):
// they are destroyed explicitly at the end of each run and vanish with the
// session in any case, so tests never leave traces on the HSM.
package funtest

import (
	"fmt"
	"sort"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
)

// StepStatus is the outcome of a single test step.
type StepStatus string

const (
	StatusPass StepStatus = "PASS"
	StatusFail StepStatus = "FAIL"
	StatusSkip StepStatus = "NOT SUPPORTED"
)

// StepResult records the outcome of one step.
type StepResult struct {
	Name     string        `json:"name"`
	Status   StepStatus    `json:"status"`
	Detail   string        `json:"detail,omitempty"`
	Duration time.Duration `json:"duration_ns,omitempty"`
}

// Result is the outcome of a whole profile run.
type Result struct {
	Profile string       `json:"profile"`
	Steps   []StepResult `json:"steps"`
}

// Counts returns the number of passed, failed and skipped steps.
func (r *Result) Counts() (pass, fail, skip int) {
	for _, s := range r.Steps {
		switch s.Status {
		case StatusPass:
			pass++
		case StatusFail:
			fail++
		case StatusSkip:
			skip++
		}
	}
	return
}

// step is one unit of a profile. Run receives an authenticated session and
// must only create session objects; handles registered via rt.cleanup are
// destroyed after the step.
type step struct {
	name string
	// needs lists mechanism codes that must be advertised by the token;
	// the step is reported NOT SUPPORTED when any is missing.
	needs []uint
	run   func(rt *runtime) error
}

// profile is a named ordered list of steps.
type profile struct {
	name        string
	description string
	steps       []step
}

// profiles is the registry of available test profiles.
var profiles = map[string]*profile{
	signVerifyProfile.name: signVerifyProfile,
}

// ProfileNames lists the available profile names.
func ProfileNames() []string {
	names := make([]string, 0, len(profiles))
	for n := range profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Run executes the named profile in the given slot.
func Run(client *p11.Client, slotID uint, pin string, profileName string) (*Result, error) {
	prof, ok := profiles[profileName]
	if !ok {
		return nil, fmt.Errorf("unknown test profile %q (available: %v)", profileName, ProfileNames())
	}

	mechs, err := client.Mechanisms(slotID)
	if err != nil {
		return nil, err
	}
	available := map[uint]bool{}
	for _, m := range mechs {
		available[m.Code] = true
	}

	sess, err := client.OpenSession(slotID, pin, false)
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	res := &Result{Profile: prof.name}
	for _, st := range prof.steps {
		res.Steps = append(res.Steps, runStep(sess, st, available))
	}
	return res, nil
}

func runStep(sess *p11.Session, st step, available map[uint]bool) StepResult {
	for _, code := range st.needs {
		if !available[code] {
			return StepResult{
				Name:   st.name,
				Status: StatusSkip,
				Detail: p11.MechanismName(code) + " not advertised by token",
			}
		}
	}
	rt := &runtime{sess: sess}
	start := time.Now()
	err := st.run(rt)
	dur := time.Since(start)
	rt.destroyAll()
	if err != nil {
		return StepResult{Name: st.name, Status: StatusFail, Detail: err.Error(), Duration: dur}
	}
	return StepResult{Name: st.name, Status: StatusPass, Duration: dur}
}
