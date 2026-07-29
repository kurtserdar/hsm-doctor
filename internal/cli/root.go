// Package cli wires up the hsmdoctor command tree.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "hsmdoctor",
	Short: "HSM health, security posture and PKCS#11 diagnostics",
	Long: `HSM Doctor is an open-source, vendor-neutral toolbox for discovering,
testing and assessing the security posture of Hardware Security Modules
through the standard PKCS#11 interface.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command and exits with a non-zero status on error.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
