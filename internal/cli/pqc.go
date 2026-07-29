package cli

import (
	"fmt"
	"strings"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/pqc"
	"github.com/spf13/cobra"
)

// pqcReport is the machine-readable output of the pqc command.
type pqcReport struct {
	Detection *pqc.Detection   `json:"detection"`
	Exposure  *pqc.Exposure    `json:"exposure"`
	Host      *pqc.HostOpenSSL `json:"host_openssl,omitempty"`
	Tests     []pqc.SetResult  `json:"tests,omitempty"`
}

func newPQCCmd() *cobra.Command {
	var conn connFlags
	var runTests, noHost, asJSON bool

	cmd := &cobra.Command{
		Use:   "pqc",
		Short: "Assess post-quantum readiness of a token",
		Long: `Checks which NIST post-quantum families (ML-KEM, ML-DSA, SLH-DSA) the
token advertises, how exposed the current inventory is to a future quantum
adversary, and whether the host OpenSSL installation is PQC-capable.

With --test, advertised families are functionally probed using ephemeral
session objects that leave no trace on the token.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, slot, pin, err := conn.connect(true, true)
			if err != nil {
				return err
			}
			defer client.Close()

			info, err := client.Info()
			if err != nil {
				return err
			}
			mechs, err := client.Mechanisms(slot)
			if err != nil {
				return err
			}
			det := pqc.Detect(mechs)
			det.CryptokiVersion = info.CryptokiVersion

			inv, err := inventory.Collect(client, slot, pin)
			if err != nil {
				return err
			}
			rep := &pqcReport{
				Detection: det,
				Exposure:  pqc.Assess(inv, det),
			}
			if !noHost {
				rep.Host = pqc.CheckHostOpenSSL(cmd.Context())
			}
			if runTests {
				if rep.Tests, err = pqc.RunTests(client, slot, pin, det); err != nil {
					return err
				}
			}

			if asJSON {
				return jsonEncoder(cmd.OutOrStdout()).Encode(rep)
			}
			printPQC(cmd, rep, inv.Slot.TokenLabel())
			return nil
		},
	}
	conn.register(cmd, true)
	cmd.Flags().BoolVar(&runTests, "test", false, "functionally probe advertised families with ephemeral session objects")
	cmd.Flags().BoolVar(&noHost, "no-host", false, "skip the host OpenSSL capability check")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return cmd
}

func printPQC(cmd *cobra.Command, rep *pqcReport, tokenLabel string) {
	out := cmd.OutOrStdout()
	det := rep.Detection

	fmt.Fprintf(out, "PQC Readiness — %s (Cryptoki %s)\n\n", tokenLabel, det.CryptokiVersion)

	fmt.Fprintf(out, "%-10s %-10s %-12s %s\n", "FAMILY", "STANDARD", "ADVERTISED", "MECHANISMS")
	for _, f := range det.Families {
		status := "no"
		if f.Advertised {
			status = "YES"
		} else if f.Incomplete {
			status = "PARTIAL(!)"
		}
		fmt.Fprintf(out, "%-10s %-10s %-12s %s\n", f.Family, f.FIPS, status, strings.Join(f.Mechanisms, ", "))
	}
	if len(det.VendorDefined) > 0 {
		fmt.Fprintf(out, "\nVendor-defined mechanisms advertised: %s\n", strings.Join(det.VendorDefined, ", "))
		fmt.Fprintln(out, "  (pre-standard PQC may hide here; consult vendor documentation)")
	}

	if len(rep.Tests) > 0 {
		fmt.Fprintln(out, "\nFunctional probes:")
		for _, t := range rep.Tests {
			line := fmt.Sprintf("  %-22s %-12s", t.Set, t.Status)
			if t.Detail != "" {
				line += " " + t.Detail
			}
			fmt.Fprintln(out, line)
		}
	}

	e := rep.Exposure
	fmt.Fprintln(out, "\nQuantum exposure:")
	fmt.Fprintf(out, "  Private keys:      %d total, %d classical, %d post-quantum\n",
		e.TotalPrivateKeys, e.ClassicalPrivateKeys, e.PQCPrivateKeys)
	fmt.Fprintf(out, "  HNDL exposure:     %d classical decrypt/unwrap key(s)\n", e.HarvestNowDecryptLater)
	fmt.Fprintf(out, "  Classical certs:   %d\n", e.ClassicalCertificates)
	fmt.Fprintf(out, "  Summary:           %s\n", e.Summary)

	if h := rep.Host; h != nil {
		fmt.Fprintln(out, "\nHost OpenSSL:")
		if !h.Available {
			fmt.Fprintln(out, "  not available on this host")
		} else {
			fmt.Fprintf(out, "  %s — ML-KEM: %s, ML-DSA: %s, SLH-DSA: %s\n",
				h.Version, yesNo(h.MLKEM), yesNo(h.MLDSA), yesNo(h.SLHDSA))
		}
	}

	fmt.Fprintf(out, "\nVerdict: %s\n", det.Verdict)
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func init() {
	rootCmd.AddCommand(newPQCCmd())
}
