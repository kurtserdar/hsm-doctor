package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/doctor"
	"github.com/kurtserdar/hsm-doctor/internal/funtest"
	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/report"
	"github.com/kurtserdar/hsm-doctor/internal/version"
	"github.com/spf13/cobra"
)

func newDoctorCmd() *cobra.Command {
	var conn connFlags
	var packNames []string
	var withTests bool
	var vendorConfig, format, failOn, advisories string

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "One-shot health diagnosis: inventory, posture, certificates, PQC and more",
		Long: `Runs the core checks against a token and distills them into a single
prioritized diagnosis: an overall verdict (healthy / attention / critical), the
health score and the most important issues first, each with a suggested action.

By default it is read-only and fast (inventory, posture, certificate expiry and
post-quantum exposure). --with-tests adds an ephemeral key-generation and
signing smoke test; --vendor-config folds in appliance health.

Only object metadata is read; private key material never leaves the HSM.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "text" && format != "json" {
				return fmt.Errorf("unknown format %q (want text or json)", format)
			}
			threshold, err := parseVerdictThreshold(failOn)
			if err != nil {
				return err
			}
			cfg, err := resolveRuleConfig("", packNames)
			if err != nil {
				return err
			}

			client, slot, pin, err := conn.connect(true, true)
			if err != nil {
				return err
			}
			defer client.Close()

			inv, err := inventory.Collect(client, slot, pin)
			if err != nil {
				return err
			}
			res := policy.Evaluate(inv, cfg, time.Now())
			rep := report.New(version.Version, inv, res)
			rep.RulePacks = cfg.SourcePacks

			if vendorConfig != "" {
				vcfg, err := loadVendorConfig(vendorConfig)
				if err != nil {
					return err
				}
				if v := collectVendor(cmd.Context(), cmd.ErrOrStderr(), vcfg, inv.Module, inv.Slot.Token); v != nil {
					rep.Vendor = v
					res.AddFindings(v.Findings...)
					rep.Score = res.Score
				}
			}

			if err := mergeAdvisories(res, rep, inv, advisories); err != nil {
				return err
			}

			var tests *funtest.Result
			if withTests {
				if tests, err = funtest.Run(client, slot, pin, "sign-verify"); err != nil {
					return err
				}
			}

			diag := doctor.Build(version.Version, doctor.Input{
				Report:    rep,
				Tests:     tests,
				TestsRan:  withTests,
				VendorRan: vendorConfig != "",
			})

			if format == "json" {
				if err := diag.JSON(os.Stdout); err != nil {
					return err
				}
			} else if err := diag.Text(os.Stdout); err != nil {
				return err
			}

			if threshold != "" && diag.Verdict.Rank() >= threshold.Rank() {
				return fmt.Errorf("diagnosis verdict %q meets --fail-on %q", diag.Verdict, failOn)
			}
			return nil
		},
	}
	conn.register(cmd, true)
	cmd.Flags().StringArrayVar(&packNames, "pack", nil, "policy pack to apply (embedded name or file path; repeatable)")
	cmd.Flags().BoolVar(&withTests, "with-tests", false, "also run an ephemeral key-generation and signing smoke test")
	cmd.Flags().StringVar(&vendorConfig, "vendor-config", "", "vendor configuration file enabling appliance-level checks")
	cmd.Flags().StringVar(&advisories, "advisories", "", "advisory feed file to match firmware/library versions against (default: built-in feed)")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit non-zero when the verdict is at or above this level (attention or critical)")
	return cmd
}

// parseVerdictThreshold validates a --fail-on value.
func parseVerdictThreshold(s string) (doctor.Verdict, error) {
	switch s {
	case "":
		return "", nil
	case string(doctor.VerdictAttention):
		return doctor.VerdictAttention, nil
	case string(doctor.VerdictCritical):
		return doctor.VerdictCritical, nil
	default:
		return "", fmt.Errorf("invalid --fail-on value %q (want attention or critical)", s)
	}
}

func init() {
	rootCmd.AddCommand(newDoctorCmd())
}
