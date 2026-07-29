package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/rules"
	"github.com/spf13/cobra"
)

// resolveRuleConfig turns the --rules / --pack flags into one merged policy
// configuration. Precedence:
//   - --rules FILE replaces everything (backward compatible),
//   - one or more --pack values (embedded names or file paths) are merged,
//   - neither: the built-in default rule set.
func resolveRuleConfig(rulesPath string, packNames []string) (*policy.Config, error) {
	if rulesPath != "" && len(packNames) > 0 {
		return nil, fmt.Errorf("--rules and --pack are mutually exclusive; list every pack with --pack instead")
	}

	if rulesPath != "" {
		data, err := os.ReadFile(rulesPath)
		if err != nil {
			return nil, fmt.Errorf("reading rules file: %w", err)
		}
		cfg, err := policy.Load(data)
		if err != nil {
			return nil, err
		}
		cfg.SourcePacks = []string{sourceName(cfg, rulesPath)}
		return cfg, nil
	}

	if len(packNames) == 0 {
		cfg, err := policy.Load(rules.Default)
		if err != nil {
			return nil, err
		}
		cfg.SourcePacks = []string{"default"}
		return cfg, nil
	}

	var configs []*policy.Config
	var names []string
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
		configs = append(configs, cfg)
		names = append(names, sourceName(cfg, name))
	}
	merged, err := policy.Merge(configs...)
	if err != nil {
		return nil, err
	}
	merged.SourcePacks = names
	return merged, nil
}

// sourceName prefers the pack's declared name over its file path.
func sourceName(cfg *policy.Config, fallback string) string {
	if cfg.Pack != nil && cfg.Pack.Name != "" {
		return cfg.Pack.Name
	}
	return strings.TrimSuffix(filepath.Base(fallback), filepath.Ext(fallback))
}

func newPacksCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "packs",
		Short: "List the built-in policy packs",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%-15s %-6s %s\n", "PACK", "RULES", "DESCRIPTION")

			printPack := func(name string, data []byte) error {
				cfg, err := policy.Load(data)
				if err != nil {
					return fmt.Errorf("pack %s: %w", name, err)
				}
				desc := ""
				if cfg.Pack != nil {
					desc = strings.Join(strings.Fields(cfg.Pack.Description), " ")
				}
				fmt.Fprintf(out, "%-15s %-6d %s\n", name, len(cfg.Rules), desc)
				return nil
			}

			if err := printPack("default", rules.Default); err != nil {
				return err
			}
			for _, p := range rules.Packs() {
				if err := printPack(p.Name, p.Data); err != nil {
					return err
				}
			}
			fmt.Fprintln(out, "\nCombine packs with repeated --pack flags, e.g.: hsmdoctor scan --pack nist --pack strict ...")
			return nil
		},
	}
}

func init() {
	rootCmd.AddCommand(newPacksCmd())
}
