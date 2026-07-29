package cli

import (
	"fmt"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/certmon"
	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/spf13/cobra"
)

func newCertsCmd() *cobra.Command {
	var conn connFlags
	var warnDays int
	var asJSON bool
	var failOn string

	cmd := &cobra.Command{
		Use:   "certs",
		Short: "List certificates on a token with their expiry status",
		Long: `Lists every X.509 certificate stored on the token together with its
expiry status, most urgent first. Designed for cron and CI usage via
--fail-on.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if failOn != "" && failOn != string(certmon.StatusExpired) && failOn != string(certmon.StatusExpiring) {
				return fmt.Errorf("invalid --fail-on value %q (want expired or expiring)", failOn)
			}

			pin, err := conn.resolvePIN(true)
			if err != nil {
				return err
			}
			client, err := p11.Open(conn.module)
			if err != nil {
				return err
			}
			defer client.Close()

			inv, err := inventory.Collect(client, conn.slot, pin)
			if err != nil {
				return err
			}
			entries := certmon.Classify(inv, time.Now(), warnDays)

			if asJSON {
				if err := jsonEncoder(cmd.OutOrStdout()).Encode(entries); err != nil {
					return err
				}
			} else {
				printCerts(cmd, entries, warnDays)
			}

			_, expiring, expired := certmon.Counts(entries)
			switch failOn {
			case string(certmon.StatusExpired):
				if expired > 0 {
					return fmt.Errorf("%d expired certificate(s)", expired)
				}
			case string(certmon.StatusExpiring):
				if expired+expiring > 0 {
					return fmt.Errorf("%d certificate(s) expired or expiring within %d days", expired+expiring, warnDays)
				}
			}
			return nil
		},
	}
	conn.register(cmd, true)
	cmd.Flags().IntVar(&warnDays, "warn-days", 30, "days before expiry to flag a certificate as expiring")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit non-zero on: expired (only expired) or expiring (expired + expiring)")
	return cmd
}

func printCerts(cmd *cobra.Command, entries []certmon.Entry, warnDays int) {
	out := cmd.OutOrStdout()
	if len(entries) == 0 {
		fmt.Fprintln(out, "No certificates found on the token.")
		return
	}
	fmt.Fprintf(out, "%-22s %-38s %-12s %s\n", "LABEL", "SUBJECT", "EXPIRES", "STATUS")
	for _, e := range entries {
		var status string
		switch e.Status {
		case certmon.StatusExpired:
			status = fmt.Sprintf("EXPIRED (%d days ago)", -e.DaysLeft)
		case certmon.StatusExpiring:
			status = fmt.Sprintf("EXPIRING (%d days left)", e.DaysLeft)
		default:
			status = "OK"
		}
		subject := e.Subject
		if len(subject) > 38 {
			subject = subject[:35] + "..."
		}
		fmt.Fprintf(out, "%-22s %-38s %-12s %s\n", e.Label, subject, e.NotAfter.Format("2006-01-02"), status)
	}
	ok, expiring, expired := certmon.Counts(entries)
	fmt.Fprintf(out, "\n%d ok, %d expiring within %d days, %d expired\n", ok, expiring, warnDays, expired)
}

func init() {
	rootCmd.AddCommand(newCertsCmd())
}
