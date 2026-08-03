package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/kmip"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/spf13/cobra"
)

func newKMIPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kmip",
		Short: "Diagnose a KMIP key-management server (read-only)",
		Long: `Connect to a KMIP server over (mutual) TLS, locate its managed objects and
evaluate their security posture. Read-only: no keys are created, modified or
destroyed.`,
	}
	cmd.AddCommand(newKMIPScanCmd())
	return cmd
}

func newKMIPScanCmd() *cobra.Command {
	var cfg kmip.Config
	var format, outPath, failOn string

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Inventory a KMIP server and report its security posture",
		RunE: func(cmd *cobra.Command, args []string) error {
			inv, err := kmip.Collect(cfg, time.Now())
			if err != nil {
				return err
			}
			rep := kmip.Evaluate(inv)

			out, closeOut, err := openOutput(outPath)
			if err != nil {
				return err
			}
			defer closeOut()

			switch format {
			case "text":
				printKMIP(cmd, rep)
			case "json":
				if err := jsonEncoder(out).Encode(rep); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unknown format %q (want text or json)", format)
			}
			return checkKMIPFailOn(failOn, rep)
		},
	}
	cmd.Flags().StringVar(&cfg.Endpoint, "endpoint", "", "KMIP server address host:port (required)")
	cmd.Flags().StringVar(&cfg.ServerCA, "server-ca", "", "PEM CA bundle to verify the server certificate")
	cmd.Flags().StringVar(&cfg.ClientCert, "client-cert", "", "client certificate for mutual TLS")
	cmd.Flags().StringVar(&cfg.ClientKey, "client-key", "", "client private key for mutual TLS")
	cmd.Flags().BoolVar(&cfg.Insecure, "insecure", false, "skip server certificate verification (labs only)")
	cmd.Flags().DurationVar(&cfg.Timeout, "timeout", 15*time.Second, "connection and request timeout")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().StringVar(&outPath, "out", "-", "output file ('-' for stdout)")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit non-zero if findings at or above this severity exist (critical, high, medium, low)")
	_ = cmd.MarkFlagRequired("endpoint")
	return cmd
}

func printKMIP(cmd *cobra.Command, rep *kmip.Report) {
	out := cmd.OutOrStdout()
	inv := rep.Inventory
	fmt.Fprintf(out, "KMIP posture — %s (KMIP %s)\n\n", inv.Endpoint, inv.ProtocolVersion)
	fmt.Fprintf(out, "Health Score: %d/100\n\n", rep.Score)

	bySev := map[policy.Severity][]policy.Finding{}
	for _, f := range rep.Findings {
		bySev[f.Severity] = append(bySev[f.Severity], f)
	}
	if len(rep.Findings) == 0 {
		fmt.Fprintf(out, "No findings across %d managed object(s).\n\n", len(inv.Objects))
	}
	for _, sev := range []policy.Severity{policy.SevCritical, policy.SevHigh, policy.SevMedium, policy.SevLow} {
		fs := bySev[sev]
		if len(fs) == 0 {
			continue
		}
		fmt.Fprintf(out, "%s (%d)\n", strings.ToUpper(string(sev)), len(fs))
		for _, f := range fs {
			fmt.Fprintf(out, "  [%s] %s\n", f.RuleID, f.Title)
			fmt.Fprintf(out, "          %s\n", f.Object)
			if f.Detail != "" {
				fmt.Fprintf(out, "          %s\n", f.Detail)
			}
			if f.Remediation != "" {
				fmt.Fprintf(out, "          fix: %s\n", f.Remediation)
			}
		}
		fmt.Fprintln(out)
	}

	fmt.Fprintf(out, "OBJECTS (%d)\n", len(inv.Objects))
	for _, o := range inv.Objects {
		name := ""
		if len(o.Names) > 0 {
			name = " " + o.Names[0]
		}
		size := ""
		if o.Length > 0 {
			size = fmt.Sprintf(" %d", o.Length)
		}
		usage := ""
		if len(o.UsageMask) > 0 {
			usage = " usage=" + strings.Join(o.UsageMask, "|")
		}
		fmt.Fprintf(out, "  %-14s%s (%s)  %s%s  state=%s%s\n",
			o.Type, name, o.ID, o.Algorithm, size, o.State, usage)
	}
}

func checkKMIPFailOn(threshold string, rep *kmip.Report) error {
	if threshold == "" {
		return nil
	}
	sev := policy.Severity(threshold)
	if !sev.Valid() {
		return fmt.Errorf("invalid --fail-on severity %q", threshold)
	}
	count := 0
	for _, f := range rep.Findings {
		if f.Severity.Rank() <= sev.Rank() {
			count++
		}
	}
	if count > 0 {
		return fmt.Errorf("%d KMIP finding(s) at or above severity %s", count, sev)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(newKMIPCmd())
}
