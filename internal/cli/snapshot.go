package cli

import (
	"fmt"

	"github.com/kurtserdar/hsm-doctor/internal/inventory"
	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/snapshot"
	"github.com/kurtserdar/hsm-doctor/internal/version"
	"github.com/spf13/cobra"
)

func newSnapshotCmd() *cobra.Command {
	var conn connFlags
	var outPath string

	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Record the current state of a token for later drift detection",
		Long: `Collects the metadata inventory of a token and writes it to a JSON file.
Compare two snapshots later with "hsmdoctor diff" to detect drift.`,
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

			inv, err := inventory.Collect(client, conn.slot, pin)
			if err != nil {
				return err
			}

			out, closeOut, err := openOutput(outPath)
			if err != nil {
				return err
			}
			defer closeOut()
			if err := snapshot.New(version.Version, inv).Write(out); err != nil {
				return err
			}
			if outPath != "" && outPath != "-" {
				fmt.Fprintf(cmd.ErrOrStderr(), "Snapshot with %d object(s) written to %s\n", len(inv.Objects), outPath)
			}
			return nil
		},
	}
	conn.register(cmd, true)
	cmd.Flags().StringVar(&outPath, "out", "-", "output file ('-' for stdout)")
	return cmd
}

func newDiffCmd() *cobra.Command {
	var asJSON bool
	var exitCode bool

	cmd := &cobra.Command{
		Use:   "diff <old-snapshot.json> <new-snapshot.json>",
		Short: "Compare two snapshots and report drift",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			oldSnap, err := snapshot.LoadFile(args[0])
			if err != nil {
				return err
			}
			newSnap, err := snapshot.LoadFile(args[1])
			if err != nil {
				return err
			}

			d := snapshot.Compare(oldSnap.Inventory, newSnap.Inventory)
			if asJSON {
				enc := jsonEncoder(cmd.OutOrStdout())
				if err := enc.Encode(d); err != nil {
					return err
				}
			} else {
				d.Text(cmd.OutOrStdout())
			}
			if exitCode && !d.Empty() {
				return fmt.Errorf("%d change(s) detected", d.Count())
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	cmd.Flags().BoolVar(&exitCode, "exit-code", false, "exit non-zero when drift is detected (for scripting)")
	return cmd
}

func init() {
	rootCmd.AddCommand(newSnapshotCmd())
	rootCmd.AddCommand(newDiffCmd())
}
