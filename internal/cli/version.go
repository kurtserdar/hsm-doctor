package cli

import (
	"fmt"

	"github.com/kurtserdar/hsm-doctor/internal/version"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("hsmdoctor %s (commit %s)\n", version.Version, version.Commit)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
