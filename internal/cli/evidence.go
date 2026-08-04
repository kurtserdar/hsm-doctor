package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/evidence"
	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/version"
	"github.com/kurtserdar/hsm-doctor/rules"
	"github.com/spf13/cobra"
)

func newEvidenceCmd() *cobra.Command {
	var conn connFlags
	var packNames []string
	var format, outPath string

	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Generate an auditor-facing compliance evidence report for policy packs",
		Long: `Evaluates a token against one or more compliance packs and produces an
evidence report with a pass / fail / not-applicable verdict per control and the
objects behind each failure.

Controls map directly to the pack's rules: a control fails when a scan with the
same pack produces a finding for its rule. The report is guidance, not a
certification statement.

Only object metadata is read; private key material never leaves the HSM.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(packNames) == 0 {
				return fmt.Errorf("at least one --pack is required (see 'hsmdoctor packs')")
			}
			if format != "html" && format != "json" {
				return fmt.Errorf("unknown format %q (want html or json)", format)
			}
			packs, err := loadEvidencePacks(packNames)
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

			rep := evidence.Build(version.Version, inv, packs, time.Now())

			out, closeOut, err := openOutput(outPath)
			if err != nil {
				return err
			}
			defer closeOut()

			if format == "json" {
				return rep.JSON(out)
			}
			return rep.HTML(out)
		},
	}
	conn.register(cmd, true)
	cmd.Flags().StringArrayVar(&packNames, "pack", nil, "compliance pack to assess (embedded name or file path; repeatable, required)")
	cmd.Flags().StringVar(&format, "format", "html", "output format: html or json")
	cmd.Flags().StringVar(&outPath, "out", "-", "output file ('-' for stdout)")
	return cmd
}

// loadEvidencePacks resolves each pack name to its parsed rules, keeping the
// packs separate so the report can group controls by pack.
func loadEvidencePacks(packNames []string) ([]evidence.LoadedPack, error) {
	var packs []evidence.LoadedPack
	for _, name := range packNames {
		data, ok := rules.PackData(name)
		if !ok {
			var err error
			if data, err = os.ReadFile(name); err != nil {
				return nil, fmt.Errorf("pack %q: not an embedded pack (see 'hsmdoctor packs') and not a readable file", name)
			}
		}
		cfg, err := policy.Load(data)
		if err != nil {
			return nil, fmt.Errorf("pack %q: %w", name, err)
		}
		lp := evidence.LoadedPack{Name: sourceName(cfg, name), Config: cfg}
		if cfg.Pack != nil {
			lp.Description = cfg.Pack.Description
		}
		packs = append(packs, lp)
	}
	return packs, nil
}

func init() {
	rootCmd.AddCommand(newEvidenceCmd())
}
