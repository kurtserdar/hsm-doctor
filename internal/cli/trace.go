package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/trace"
	"github.com/spf13/cobra"
)

func newTraceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trace",
		Short: "Work with PKCS#11 call traces from the Flight Recorder shim",
		Long: `Analyze PKCS#11 call traces produced by the HSM Doctor Flight Recorder
shim (see docs/trace.md). Traces are metadata only — no PINs, key material
or plaintext are ever recorded.`,
	}
	cmd.AddCommand(newTraceAnalyzeCmd(), newTraceSummaryCmd())
	return cmd
}

// openTrace reads a trace from a path or stdin ("-").
func openTrace(path string) ([]trace.Event, error) {
	if path == "" || path == "-" {
		return trace.Read(os.Stdin)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return trace.Read(f)
}

func newTraceAnalyzeCmd() *cobra.Command {
	var asJSON bool
	var failOnError bool

	cmd := &cobra.Command{
		Use:   "analyze [trace.jsonl]",
		Short: "Analyze a trace for leaks, ordering issues and errors",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := ""
			if len(args) == 1 {
				path = args[0]
			}
			events, err := openTrace(path)
			if err != nil {
				return err
			}
			a := trace.Analyze(events)

			if asJSON {
				if err := jsonEncoder(cmd.OutOrStdout()).Encode(a); err != nil {
					return err
				}
			} else {
				printAnalysis(cmd, a)
			}
			if failOnError {
				for _, f := range a.Findings {
					if f.Severity == trace.SevError {
						return fmt.Errorf("trace analysis found error-level issues")
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	cmd.Flags().BoolVar(&failOnError, "fail-on-error", false, "exit non-zero when error-level findings exist")
	return cmd
}

func newTraceSummaryCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "summary [trace.jsonl]",
		Short: "Show per-function call counts and timing",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := ""
			if len(args) == 1 {
				path = args[0]
			}
			events, err := openTrace(path)
			if err != nil {
				return err
			}
			a := trace.Analyze(events)
			if asJSON {
				return jsonEncoder(cmd.OutOrStdout()).Encode(a.Stats)
			}
			printStats(cmd, a)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return cmd
}

func printAnalysis(cmd *cobra.Command, a *trace.Analysis) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Analyzed %d PKCS#11 call(s)\n\n", a.Events)
	if len(a.Findings) == 0 {
		fmt.Fprintln(out, "No issues detected.")
	} else {
		for _, f := range a.Findings {
			seqs := ""
			if len(f.Seqs) > 0 {
				seqs = fmt.Sprintf(" (seq %v)", f.Seqs)
			}
			fmt.Fprintf(out, "[%-7s] %-16s %s%s\n", f.Severity, f.Check, f.Message, seqs)
		}
	}
	fmt.Fprintln(out)
	printStats(cmd, a)
}

func printStats(cmd *cobra.Command, a *trace.Analysis) {
	out := cmd.OutOrStdout()
	if len(a.Stats) == 0 {
		return
	}
	fmt.Fprintf(out, "%-26s %7s %7s %10s %10s\n", "FUNCTION", "CALLS", "ERRORS", "TOTAL", "MAX")
	for _, s := range a.Stats {
		fmt.Fprintf(out, "%-26s %7d %7d %10s %10s\n",
			s.Function, s.Calls, s.Errors,
			time.Duration(s.TotalNS).Round(time.Microsecond),
			time.Duration(s.MaxNS).Round(time.Microsecond))
	}
}

func init() {
	rootCmd.AddCommand(newTraceCmd())
}
