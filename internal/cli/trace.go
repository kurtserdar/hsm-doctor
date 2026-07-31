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
	cmd.AddCommand(newTraceAnalyzeCmd(), newTraceSummaryCmd(), newTraceCoverageCmd())
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

func newTraceCoverageCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "coverage [trace.jsonl]",
		Short: "Report which PKCS#11 functions the trace exercised",
		Long: `Report PKCS#11 function coverage for a trace: how many of the functions
the Flight Recorder can observe were actually exercised, and which were not.
Useful for gauging how thoroughly a test suite drives its PKCS#11 module.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := ""
			if len(args) == 1 {
				path = args[0]
			}
			events, err := openTrace(path)
			if err != nil {
				return err
			}
			cov := trace.CoverageOf(events)
			if asJSON {
				return jsonEncoder(cmd.OutOrStdout()).Encode(cov)
			}
			printCoverage(cmd, cov)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return cmd
}

func printCoverage(cmd *cobra.Command, cov *trace.Coverage) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "PKCS#11 function coverage: %d/%d (%.0f%%)\n\n", cov.Covered, cov.Total, cov.Percent)

	if len(cov.Exercise) > 0 {
		fmt.Fprintf(out, "EXERCISED (%d)\n", len(cov.Exercise))
		for _, c := range cov.Exercise {
			fmt.Fprintf(out, "  %-24s %d\n", c.Function, c.Calls)
		}
		fmt.Fprintln(out)
	}
	if len(cov.Missing) > 0 {
		fmt.Fprintf(out, "NOT EXERCISED (%d)\n", len(cov.Missing))
		for _, fn := range cov.Missing {
			fmt.Fprintf(out, "  %s\n", fn)
		}
	}
	if len(cov.Unexpected) > 0 {
		fmt.Fprintf(out, "\nUNRECOGNIZED (%d) — recorded but not in the known set\n", len(cov.Unexpected))
		for _, fn := range cov.Unexpected {
			fmt.Fprintf(out, "  %s\n", fn)
		}
	}
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
