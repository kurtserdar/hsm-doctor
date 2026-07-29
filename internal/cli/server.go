package cli

import (
	"fmt"
	"os"

	"github.com/kurtserdar/hsm-doctor/internal/server"
	"github.com/kurtserdar/hsm-doctor/internal/store"
	"github.com/kurtserdar/hsm-doctor/internal/version"
	"github.com/spf13/cobra"
)

func newServerCmd() *cobra.Command {
	var listen, dbPath, enrollToken, enrollTokenEnv string

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run the central server collecting reports from agents",
		Long: `Runs HSM Doctor in central mode: no local PKCS#11 module is loaded.
Agents enrolled with the shared enrollment token push their scan reports
here; the server stores history, detects drift and serves the fleet
dashboard, REST API and Prometheus metrics.

The default listen address is loopback. When exposing the server to agents
on other hosts, front it with TLS and change --listen deliberately.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if enrollToken == "" && enrollTokenEnv != "" {
				enrollToken = os.Getenv(enrollTokenEnv)
				if enrollToken == "" {
					return fmt.Errorf("environment variable %s is empty or not set", enrollTokenEnv)
				}
			}
			if enrollToken == "" {
				fmt.Fprintln(cmd.ErrOrStderr(), "Warning: no enrollment token configured; new agents cannot enroll.")
			}

			if dbPath == "" {
				var err error
				if dbPath, err = store.DefaultPath(); err != nil {
					return err
				}
			}
			db, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Fleet database: %s\n", dbPath)

			srv := server.NewCentral(version.Version, db, enrollToken)
			defer srv.Close()
			return srv.ListenAndServe(listen)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:8080", "listen address")
	cmd.Flags().StringVar(&dbPath, "db", "", "fleet database path (default: ~/.local/share/hsmdoctor/hsmdoctor.db)")
	cmd.Flags().StringVar(&enrollToken, "enroll-token", "", "shared token agents use to enroll (WARNING: visible in process list; prefer --enroll-token-env)")
	cmd.Flags().StringVar(&enrollTokenEnv, "enroll-token-env", "", "name of the environment variable holding the enrollment token")
	return cmd
}

func init() {
	rootCmd.AddCommand(newServerCmd())
}
