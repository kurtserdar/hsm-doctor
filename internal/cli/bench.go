package cli

import (
	"fmt"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/bench"
	"github.com/spf13/cobra"
)

func newBenchCmd() *cobra.Command {
	var conn connFlags
	var duration time.Duration
	var maxOps, sessions int
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "bench",
		Short: "Measure token performance with strictly bounded load",
		Long: `Measures signing and encryption throughput using ephemeral session
objects. Every run is capped by both duration and an absolute operation
budget per primitive, so a benchmark cannot overload a token indefinitely.

Avoid running benchmarks against production HSMs serving live traffic.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, slot, pin, err := conn.connect(true, true)
			if err != nil {
				return err
			}
			defer client.Close()

			opts := bench.Options{Duration: duration, MaxOps: maxOps, Sessions: sessions}.Normalize()
			fmt.Fprintf(cmd.ErrOrStderr(),
				"Running bounded benchmark: %s or %d ops per primitive, %d session(s)\n\n",
				opts.Duration, opts.MaxOps, opts.Sessions)

			res, err := bench.Run(client, slot, pin, opts)
			if err != nil {
				return err
			}

			if asJSON {
				return jsonEncoder(cmd.OutOrStdout()).Encode(res)
			}
			printBench(cmd, res)
			return nil
		},
	}
	conn.register(cmd, true)
	cmd.Flags().DurationVar(&duration, "duration", bench.DefaultDuration,
		fmt.Sprintf("max duration per primitive (capped at %s)", bench.MaxDuration))
	cmd.Flags().IntVar(&maxOps, "max-ops", bench.DefaultMaxOps,
		fmt.Sprintf("max operations per primitive (capped at %d)", bench.HardMaxOps))
	cmd.Flags().IntVar(&sessions, "sessions", bench.DefaultSessions,
		fmt.Sprintf("concurrent sessions (capped at %d)", bench.MaxSessions))
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return cmd
}

func printBench(cmd *cobra.Command, res *bench.Result) {
	out := cmd.OutOrStdout()
	for _, m := range res.Measurements {
		switch {
		case !m.Supported:
			fmt.Fprintf(out, "%-30s NOT SUPPORTED  %s\n", m.Name, m.Error)
		case m.Error != "":
			fmt.Fprintf(out, "%-30s FAILED         %s\n", m.Name, m.Error)
		default:
			fmt.Fprintf(out, "%-30s %8.1f ops/sec  (%d ops in %s)\n",
				m.Name, m.OpsPerSec, m.Ops, m.Elapsed.Round(time.Millisecond))
		}
	}
}

func init() {
	rootCmd.AddCommand(newBenchCmd())
}
