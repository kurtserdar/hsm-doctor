package cli

import (
	"fmt"
	"os"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/p11names"
	"github.com/kurtserdar/hsm-doctor/internal/preflight"
	"github.com/spf13/cobra"
)

// exitPostpone is the process exit code for a "postpone" verdict, kept
// distinct from a general error (1) so automation can tell "HSM not ready,
// retry later" apart from "misconfiguration, alert a human".
const exitPostpone = 4

func newPreflightCmd() *cobra.Command {
	var conn connFlags
	var mechanisms []string
	var probe bool
	var minFreeSessions int
	var vendorConfig string
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "preflight",
		Short: "Check whether a token is ready for a key/certificate renewal",
		Long: `Runs a fast readiness gate against a token: the module loads, the
token is present and initialized, the PIN logs in, the required mechanisms are
available and enough sessions are free. With --probe it also runs an ephemeral
key-generation and signing smoke test. With --vendor-config it factors in
tamper state and HA member health.

Intended as the gate a certificate-lifecycle system calls before starting an
HSM-backed renewal. Exit codes: 0 = ready, 4 = postpone (not ready, retry
later), 1 = error talking to the module.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			codes, err := resolveMechanisms(mechanisms)
			if err != nil {
				return err
			}

			client, slot, pin, err := conn.connect(true, true)
			if err != nil {
				return err
			}
			defer client.Close()

			opts := preflight.Options{
				RequiredMechanisms: codes,
				Probe:              probe,
				MinFreeSessions:    minFreeSessions,
			}
			if vendorConfig != "" {
				cfgFile, err := loadVendorConfig(vendorConfig)
				if err != nil {
					return err
				}
				info, err := client.Info()
				if err != nil {
					return err
				}
				var token *p11.TokenInfo
				if slots, err := client.Slots(); err == nil {
					for i := range slots {
						if slots[i].ID == slot {
							token = slots[i].Token
						}
					}
				}
				opts.Vendor = collectVendor(cmd.Context(), os.Stderr, cfgFile, info, token)
			}

			res, err := preflight.Run(client, slot, pin, opts)
			if err != nil {
				return err
			}

			if asJSON {
				if err := jsonEncoder(os.Stdout).Encode(res); err != nil {
					return err
				}
			} else {
				printPreflight(res)
			}

			if !res.Ready {
				return &exitError{code: exitPostpone}
			}
			return nil
		},
	}
	conn.register(cmd, true)
	cmd.Flags().StringArrayVar(&mechanisms, "mechanism", nil,
		"required mechanism by CKM_* name or hex code (repeatable), e.g. CKM_RSA_PKCS_KEY_PAIR_GEN")
	cmd.Flags().BoolVar(&probe, "probe", false, "run an ephemeral key-generation and signing smoke test")
	cmd.Flags().IntVar(&minFreeSessions, "min-free-sessions", 0, "require at least this many free sessions on the token")
	cmd.Flags().StringVar(&vendorConfig, "vendor-config", "", "vendor config file; factors tamper and HA state into the verdict")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return cmd
}

// resolveMechanisms turns CKM_* names or hex codes into numeric codes.
func resolveMechanisms(names []string) ([]uint, error) {
	codes := make([]uint, 0, len(names))
	for _, n := range names {
		code, ok := p11names.MechanismCode(n)
		if !ok {
			return nil, fmt.Errorf("unknown mechanism %q (use a CKM_* name or 0x hex code)", n)
		}
		codes = append(codes, code)
	}
	return codes, nil
}

func printPreflight(res *preflight.Result) {
	fmt.Printf("Token: %s (slot %d)\n\n", tokenOrPlaceholder(res.Token), res.Slot)
	for _, c := range res.Checks {
		mark := map[preflight.Level]string{
			preflight.LevelOK:   "✓",
			preflight.LevelWarn: "!",
			preflight.LevelFail: "✗",
		}[c.Level]
		fmt.Printf("  %s %-12s %s\n", mark, c.Name, c.Detail)
	}
	fmt.Println()
	if res.Ready {
		fmt.Println("Verdict: READY")
		return
	}
	fmt.Println("Verdict: POSTPONE")
	for _, r := range res.Reasons {
		fmt.Printf("  - %s\n", r)
	}
}

func tokenOrPlaceholder(label string) string {
	if label == "" {
		return "(none)"
	}
	return label
}

func init() {
	rootCmd.AddCommand(newPreflightCmd())
}
