package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/regression"
	"github.com/kurtserdar/hsm-doctor/internal/report"
	"github.com/kurtserdar/hsm-doctor/internal/version"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	var conn connFlags
	var rulesPath, format, outPath, failOn, vendorConfig, caBundle, baseline, advisories string
	var packNames []string
	var baselineMaxDrop int

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a token: inventory, security posture and health score",
		Long: `Collects the metadata inventory of a token, evaluates it against the
security posture rules and reports findings with a health score.

Only object metadata is read; private key material never leaves the HSM.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := resolveRuleConfig(rulesPath, packNames)
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
			if caBundle != "" {
				data, err := os.ReadFile(caBundle)
				if err != nil {
					return fmt.Errorf("reading CA bundle: %w", err)
				}
				roots, err := inventory.ParseCABundle(data)
				if err != nil {
					return err
				}
				inventory.ValidateChains(inv, roots)
			}
			res := policy.Evaluate(inv, cfg, time.Now())
			rep := report.New(version.Version, inv, res)
			rep.RulePacks = cfg.SourcePacks

			vcfg, err := loadVendorConfig(vendorConfig)
			if err != nil {
				return err
			}
			if v := collectVendor(cmd.Context(), cmd.ErrOrStderr(), vcfg, inv.Module, inv.Slot.Token); v != nil {
				rep.Vendor = v
				res.AddFindings(v.Findings...)
				rep.Score = res.Score
			}

			if err := mergeAdvisories(res, rep, inv, advisories); err != nil {
				return err
			}

			out, closeOut, err := openOutput(outPath)
			if err != nil {
				return err
			}
			defer closeOut()

			switch format {
			case "text":
				err = rep.Text(out)
			case "json":
				err = rep.JSON(out)
			case "html":
				err = rep.HTML(out)
			case "sarif":
				err = rep.SARIF(out)
			case "cbom":
				err = rep.CBOM(out)
			default:
				return fmt.Errorf("unknown format %q (want text, json, html, sarif or cbom)", format)
			}
			if err != nil {
				return err
			}
			if err := checkBaseline(cmd, baseline, baselineMaxDrop, rep); err != nil {
				return err
			}
			return checkFailOn(failOn, res)
		},
	}
	conn.register(cmd, true)
	cmd.Flags().StringVar(&rulesPath, "rules", "", "path to a custom rules YAML file replacing all packs")
	cmd.Flags().StringArrayVar(&packNames, "pack", nil, "policy pack to apply (embedded name or file path; repeatable, see 'hsmdoctor packs')")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, json, html, sarif or cbom")
	cmd.Flags().StringVar(&outPath, "out", "-", "output file ('-' for stdout)")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit non-zero if findings at or above this severity exist (critical, high, medium, low)")
	cmd.Flags().StringVar(&caBundle, "ca-bundle", "", "PEM trust anchors; enables certificate chain validation (HSM-019)")
	cmd.Flags().StringVar(&vendorConfig, "vendor-config", "", "vendor configuration file enabling appliance-level checks")
	cmd.Flags().StringVar(&advisories, "advisories", "", "advisory feed file to match firmware/library versions against (default: built-in feed)")
	cmd.Flags().StringVar(&baseline, "baseline", "", "compare against a saved JSON report (from --format json) and exit non-zero on posture regression")
	cmd.Flags().IntVar(&baselineMaxDrop, "baseline-max-drop", regression.DefaultScoreDropThreshold, "health-score drop that counts as a regression for --baseline")
	return cmd
}

// openOutput opens the report destination ('-' means stdout).
func openOutput(path string) (io.Writer, func(), error) {
	if path == "" || path == "-" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("creating output file: %w", err)
	}
	return f, func() { _ = f.Close() }, nil
}

// checkBaseline compares the current report against a saved JSON report and
// returns a non-zero-exit error when the posture regressed (health-score drop
// or a new critical/high finding). The human-readable summary goes to stderr
// so it never pollutes the report written to stdout. It reuses the same
// detection engine as the fleet server, keeping the two consistent.
func checkBaseline(cmd *cobra.Command, path string, maxDrop int, rep *report.Report) error {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading baseline: %w", err)
	}
	var base report.Report
	if err := json.Unmarshal(data, &base); err != nil {
		return fmt.Errorf("parsing baseline report %q: %w", path, err)
	}
	reg := regression.Detect(base.Score, rep.Score, base.Findings, rep.Findings, maxDrop)
	if reg == nil {
		return nil
	}
	w := cmd.ErrOrStderr()
	fmt.Fprintf(w, "\nPosture regression vs baseline %s:\n", path)
	for _, r := range reg.Reasons {
		fmt.Fprintf(w, "  - %s\n", r)
	}
	return fmt.Errorf("posture regressed against baseline (score %d \u2192 %d)", base.Score, rep.Score)
}

// checkFailOn turns findings at or above the threshold into a non-zero exit.
func checkFailOn(threshold string, res *policy.Result) error {
	if threshold == "" {
		return nil
	}
	sev := policy.Severity(threshold)
	if !sev.Valid() {
		return fmt.Errorf("invalid --fail-on severity %q", threshold)
	}
	count := 0
	for _, f := range res.Findings {
		if f.Severity.Rank() <= sev.Rank() {
			count++
		}
	}
	if count > 0 {
		return fmt.Errorf("%d finding(s) at or above severity %s", count, sev)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(newScanCmd())
}
