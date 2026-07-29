// Package bench measures token performance with strictly bounded load.
//
// Every run is capped by both wall-clock duration and an absolute operation
// budget per primitive, so a benchmark can never hammer a production HSM
// indefinitely. All key material is ephemeral (session objects only).
package bench

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
)

// Limits protecting tokens from unbounded load.
const (
	DefaultDuration = 3 * time.Second
	MaxDuration     = 60 * time.Second
	DefaultMaxOps   = 5000
	HardMaxOps      = 1_000_000
	DefaultSessions = 1
	MaxSessions     = 32
)

// Options bounds a benchmark run.
type Options struct {
	Duration time.Duration `json:"duration_ns"`
	MaxOps   int           `json:"max_ops"`
	Sessions int           `json:"sessions"`
}

// Normalize applies defaults and clamps every option to its safety limit.
func (o Options) Normalize() Options {
	if o.Duration <= 0 {
		o.Duration = DefaultDuration
	}
	if o.Duration > MaxDuration {
		o.Duration = MaxDuration
	}
	if o.MaxOps <= 0 {
		o.MaxOps = DefaultMaxOps
	}
	if o.MaxOps > HardMaxOps {
		o.MaxOps = HardMaxOps
	}
	if o.Sessions <= 0 {
		o.Sessions = DefaultSessions
	}
	if o.Sessions > MaxSessions {
		o.Sessions = MaxSessions
	}
	return o
}

// Measurement is the result for one primitive.
type Measurement struct {
	Name      string        `json:"name"`
	Supported bool          `json:"supported"`
	Ops       int64         `json:"ops"`
	Elapsed   time.Duration `json:"elapsed_ns"`
	OpsPerSec float64       `json:"ops_per_sec"`
	Error     string        `json:"error,omitempty"`
}

// Result is a full benchmark run.
type Result struct {
	Options      Options       `json:"options"`
	Measurements []Measurement `json:"measurements"`
}

// Run executes all primitives sequentially, each bounded by opts.
func Run(client *p11.Client, slotID uint, pin string, opts Options) (*Result, error) {
	opts = opts.Normalize()

	mechs, err := client.Mechanisms(slotID)
	if err != nil {
		return nil, err
	}
	available := map[uint]bool{}
	for _, m := range mechs {
		available[m.Code] = true
	}

	res := &Result{Options: opts}
	for _, prim := range primitives {
		res.Measurements = append(res.Measurements, runPrimitive(client, slotID, pin, prim, available, opts))
	}
	return res, nil
}

func runPrimitive(client *p11.Client, slotID uint, pin string, prim primitive, available map[uint]bool, opts Options) Measurement {
	m := Measurement{Name: prim.name}
	for _, code := range prim.needs {
		if !available[code] {
			m.Error = p11.MechanismName(code) + " not advertised by token"
			return m
		}
	}
	m.Supported = true

	// The op budget is shared across workers; the deadline bounds the run
	// even when the budget is not exhausted.
	var budget atomic.Int64
	budget.Store(int64(opts.MaxOps))
	var done atomic.Int64
	deadline := time.Now().Add(opts.Duration)

	var wg sync.WaitGroup
	errCh := make(chan error, opts.Sessions)
	start := time.Now()
	for i := 0; i < opts.Sessions; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := benchWorker(client, slotID, pin, prim, &budget, &done, deadline); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	m.Elapsed = time.Since(start)
	close(errCh)
	if err := <-errCh; err != nil {
		m.Error = err.Error()
	}

	m.Ops = done.Load()
	if m.Elapsed > 0 {
		m.OpsPerSec = float64(m.Ops) / m.Elapsed.Seconds()
	}
	return m
}

// benchWorker opens its own session, sets up its own ephemeral objects and
// loops the operation until the shared budget or the deadline is exhausted.
func benchWorker(client *p11.Client, slotID uint, pin string, prim primitive, budget, done *atomic.Int64, deadline time.Time) error {
	sess, err := client.OpenSession(slotID, pin, false)
	if err != nil {
		return err
	}
	defer sess.Close()

	op, cleanup, err := prim.setup(sess)
	if err != nil {
		return fmt.Errorf("%s setup: %w", prim.name, err)
	}
	defer cleanup()

	for time.Now().Before(deadline) {
		if budget.Add(-1) < 0 {
			return nil
		}
		if err := op(); err != nil {
			return fmt.Errorf("%s: %w", prim.name, err)
		}
		done.Add(1)
	}
	return nil
}
