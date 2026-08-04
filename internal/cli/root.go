// Package cli wires up the hsmdoctor command tree.
package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// exitError lets a command request a specific process exit code. When msg is
// empty the command has already reported everything to the user, so Execute
// exits with the code without printing an "Error:" line.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

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
		var ee *exitError
		if errors.As(err, &ee) {
			if ee.msg != "" {
				fmt.Fprintf(os.Stderr, "Error: %v\n", ee.msg)
			}
			os.Exit(ee.code)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
