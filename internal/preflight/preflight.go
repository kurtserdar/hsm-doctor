// Package preflight answers a single operational question: is a token ready,
// right now, to mint a key and sign — the check a certificate-lifecycle system
// must pass before it starts an HSM-backed renewal.
//
// It is read-only by default (module load, token state, login, mechanism
// availability and session headroom); the optional probe additionally runs an
// ephemeral key-generation and signing smoke test. Nothing is ever persisted
// on the token and no private key material is read.
package preflight

import (
	"fmt"

	"github.com/kurtserdar/hsm-doctor/internal/funtest"
	"github.com/kurtserdar/hsm-doctor/internal/p11"
	vendor "github.com/kurtserdar/hsm-doctor/internal/vendors"
)

// Level is the outcome of a single preflight check.
type Level string

const (
	// LevelOK means the check passed.
	LevelOK Level = "ok"
	// LevelWarn means the check could not be fully evaluated but does not by
	// itself block a renewal.
	LevelWarn Level = "warn"
	// LevelFail means the check failed and the token is not ready.
	LevelFail Level = "fail"
)

// Check is one named readiness check and its outcome.
type Check struct {
	Name   string `json:"name"`
	Level  Level  `json:"level"`
	Detail string `json:"detail,omitempty"`
}

// Result is the verdict of a preflight run.
type Result struct {
	Slot    uint     `json:"slot"`
	Token   string   `json:"token"`
	Ready   bool     `json:"ready"`
	Verdict string   `json:"verdict"` // "ready" or "postpone"
	Checks  []Check  `json:"checks"`
	Reasons []string `json:"reasons,omitempty"` // details of failed checks
}

// Options configures a preflight run.
type Options struct {
	// RequiredMechanisms are CKM_* codes the token must advertise (typically
	// the key-pair-generation and signing mechanisms the renewal needs).
	RequiredMechanisms []uint
	// Probe runs an ephemeral key-generation and signing smoke test when true.
	Probe bool
	// MinFreeSessions, when > 0, requires the token to report at least this
	// many additional sessions available.
	MinFreeSessions int
	// Vendor, when set, feeds tamper and HA state into the verdict.
	Vendor *vendor.Info
}

// Run executes the readiness checks and returns a verdict. It never returns an
// error for an unhealthy token — that is expressed as a "postpone" verdict;
// errors are reserved for the caller being unable to talk to the module at all.
func Run(client *p11.Client, slot uint, pin string, opts Options) (*Result, error) {
	res := &Result{Slot: slot, Verdict: "postpone"}

	slots, err := client.Slots()
	if err != nil {
		return nil, err
	}
	var token *p11.TokenInfo
	for i := range slots {
		if slots[i].ID == slot {
			token = slots[i].Token
			break
		}
	}

	// Token presence and initialization.
	switch {
	case token == nil:
		res.add("token", LevelFail, fmt.Sprintf("no token present in slot %d", slot))
	case !token.Initialized:
		res.Token = token.Label
		res.add("token", LevelFail, "token is not initialized")
	default:
		res.Token = token.Label
		res.add("token", LevelOK, fmt.Sprintf("%q present and initialized", token.Label))
	}

	// Login: verify credentials when a PIN is supplied; flag the gap when the
	// token requires login but no PIN was given (a renewal cannot proceed).
	if token != nil {
		switch {
		case pin != "":
			if s, err := client.OpenSession(slot, pin, false); err != nil {
				res.add("login", LevelFail, "user login failed: "+err.Error())
			} else {
				s.Close()
				res.add("login", LevelOK, "user login succeeded")
			}
		case token.LoginRequired:
			res.add("login", LevelFail, "token requires login but no PIN was provided")
		default:
			res.add("login", LevelWarn, "no PIN provided; login not verified")
		}
	}

	// Required mechanisms.
	if len(opts.RequiredMechanisms) > 0 && token != nil {
		mechs, err := client.Mechanisms(slot)
		if err != nil {
			res.add("mechanisms", LevelWarn, "could not list mechanisms: "+err.Error())
		} else {
			present := make(map[uint]bool, len(mechs))
			for _, m := range mechs {
				present[m.Code] = true
			}
			var missing []string
			for _, code := range opts.RequiredMechanisms {
				if !present[code] {
					missing = append(missing, p11.MechanismName(code))
				}
			}
			if len(missing) > 0 {
				res.add("mechanisms", LevelFail, "missing required mechanism(s): "+join(missing))
			} else {
				res.add("mechanisms", LevelOK, fmt.Sprintf("all %d required mechanism(s) available", len(opts.RequiredMechanisms)))
			}
		}
	}

	// Session capacity headroom.
	if opts.MinFreeSessions > 0 && token != nil {
		free, known := token.SessionCapacity()
		switch {
		case !known:
			res.add("sessions", LevelWarn, "token does not report a session limit")
		case int(free) < opts.MinFreeSessions:
			res.add("sessions", LevelFail, fmt.Sprintf("only %d free session(s), need %d", free, opts.MinFreeSessions))
		default:
			res.add("sessions", LevelOK, fmt.Sprintf("%d free session(s) available", free))
		}
	}

	// Optional keygen + sign smoke test.
	if opts.Probe && token != nil {
		tr, err := funtest.Run(client, slot, pin, "sign-verify")
		if err != nil {
			res.add("probe", LevelFail, "smoke test could not run: "+err.Error())
		} else if _, fail, _ := tr.Counts(); fail > 0 {
			res.add("probe", LevelFail, fmt.Sprintf("%d smoke-test step(s) failed", fail))
		} else {
			res.add("probe", LevelOK, "key generation and signing succeeded")
		}
	}

	// Vendor tamper and HA state.
	if opts.Vendor != nil {
		res.checkVendor(opts.Vendor)
	}

	res.finalize()
	return res, nil
}

// checkVendor folds tamper and HA state into the verdict.
func (r *Result) checkVendor(v *vendor.Info) {
	if t := v.Tamper; t != nil && t.Tampered {
		detail := "device reports a tamper condition"
		if t.Detail != "" {
			detail = t.Detail
		}
		r.add("tamper", LevelFail, detail)
	}
	if ha := v.HA; ha != nil {
		var down []string
		for _, m := range ha.Members {
			if !m.Up {
				down = append(down, m.Name)
			}
		}
		switch {
		case len(down) > 0:
			r.add("ha", LevelFail, "HA member(s) unavailable: "+join(down))
		case ha.InSync != nil && !*ha.InSync:
			r.add("ha", LevelFail, "HA group is not in sync")
		case len(ha.Members) > 0:
			r.add("ha", LevelOK, fmt.Sprintf("all %d HA member(s) up", len(ha.Members)))
		}
	}
}

// add records a check and, for failures, its reason.
func (r *Result) add(name string, level Level, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Level: level, Detail: detail})
	if level == LevelFail {
		r.Reasons = append(r.Reasons, detail)
	}
}

// finalize sets Ready and Verdict from the collected checks.
func (r *Result) finalize() {
	r.Ready = len(r.Reasons) == 0
	if r.Ready {
		r.Verdict = "ready"
	} else {
		r.Verdict = "postpone"
	}
}

func join(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}
