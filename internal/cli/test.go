package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/funtest"
	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/spf13/cobra"
)

func newTestCmd() *cobra.Command {
	var conn connFlags
	var profileName string
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Run a safe functional test profile against a token",
		Long: `Runs a functional test profile (key generation, signing, encryption)
using ephemeral session objects only. Nothing is persisted on the token and
all created objects are destroyed when the test finishes.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pin, err := conn.resolvePIN(true)
			if err != nil {
				return err
			}
			client, err := p11.Open(conn.module)
			if err != nil {
				return err
			}
			defer client.Close()

			res, err := funtest.Run(client, conn.slot, pin, profileName)
			if err != nil {
				return err
			}

			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(res); err != nil {
					return err
				}
			} else {
				printTestResult(res)
			}

			if _, fail, _ := res.Counts(); fail > 0 {
				return fmt.Errorf("%d test step(s) failed", fail)
			}
			return nil
		},
	}
	conn.register(cmd, true)
	cmd.Flags().StringVar(&profileName, "profile", "sign-verify", "test profile to run")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return cmd
}

func printTestResult(res *funtest.Result) {
	fmt.Printf("Profile: %s\n\n", res.Profile)
	for _, s := range res.Steps {
		line := fmt.Sprintf("%-32s %-14s", s.Name, s.Status)
		if s.Status == funtest.StatusPass && s.Duration > 0 {
			line += fmt.Sprintf(" (%s)", s.Duration.Round(time.Millisecond))
		}
		fmt.Println(line)
		if s.Detail != "" {
			fmt.Printf("%-32s   %s\n", "", s.Detail)
		}
	}
	pass, fail, skip := res.Counts()
	fmt.Printf("\n%d passed, %d failed, %d not supported\n", pass, fail, skip)
}

func init() {
	rootCmd.AddCommand(newTestCmd())
}
