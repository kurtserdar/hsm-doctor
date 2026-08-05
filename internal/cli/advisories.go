package cli

import (
	"fmt"
	"os"

	"github.com/kurtserdar/hsm-doctor/internal/advisory"
	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/report"
	"github.com/spf13/cobra"
)

// loadAdvisoryFeed returns the feed at path, or the built-in feed when path is
// empty.
func loadAdvisoryFeed(path string) (*advisory.Feed, error) {
	if path == "" {
		return advisory.Default()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading advisory feed: %w", err)
	}
	return advisory.Load(data)
}

// mergeAdvisories matches the token/module versions against the advisory feed
// and folds any findings into both the score (via res) and the report's
// findings list (for display). Called by scan and doctor.
func mergeAdvisories(res *policy.Result, rep *report.Report, inv *inventory.Inventory, path string) error {
	feed, err := loadAdvisoryFeed(path)
	if err != nil {
		return err
	}
	adv := feed.Evaluate(inv.Module, inv.Slot.Token)
	if len(adv) == 0 {
		return nil
	}
	res.AddFindings(adv...)
	rep.Findings = append(rep.Findings, adv...)
	rep.Score = res.Score
	return nil
}

func newAdvisoriesCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "advisories",
		Short: "List the known-vulnerability advisory feed used by scan",
		Long: `Prints the advisory feed that scan matches against firmware and PKCS#11
library versions. The built-in feed is a small, dated, illustrative starter;
supply your own authoritative feed with --advisories (here and on scan/doctor).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			feed, err := loadAdvisoryFeed(path)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Advisory feed: %s\n", feed.DataVersion)
			fmt.Fprintf(out, "%d advisor%s\n\n", len(feed.Advisories), plural(len(feed.Advisories)))
			for _, a := range feed.Advisories {
				scope := a.Match.Component
				if a.Match.Manufacturer != "" {
					scope += " " + a.Match.Manufacturer
				}
				if a.Match.Model != "" {
					scope += "/" + a.Match.Model
				}
				fmt.Fprintf(out, "  [%s] %s (%s)\n", a.ID, a.Title, a.Severity)
				fmt.Fprintf(out, "      affects %s below %s\n", scope, a.Match.FixedIn)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "advisories", "", "advisory feed file to list instead of the built-in one")
	return cmd
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func init() {
	rootCmd.AddCommand(newAdvisoriesCmd())
}
