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
	var authPath, tlsCert, tlsKey, webhookURL string

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

			resolved, err := resolveDBPath(dbPath)
			if err != nil {
				return err
			}
			db, err := store.Open(resolved)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Fleet database: %s\n", store.Redact(resolved))

			srv := server.NewCentral(version.Version, db, enrollToken)
			defer srv.Close()
			if err := applyAuth(srv, authPath); err != nil {
				return err
			}
			srv.SetWebhook(webhookURL)
			if authPath == "" {
				fmt.Fprintln(cmd.ErrOrStderr(), "Warning: API authentication is disabled; use --auth-config before exposing this server.")
			}
			return srv.ListenAndServe(listen, tlsCert, tlsKey)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:8080", "listen address")
	cmd.Flags().StringVar(&dbPath, "db", "", "SQLite path or postgres:// DSN (default: ~/.local/share/hsmdoctor/hsmdoctor.db; or HSMDOCTOR_DB)")
	cmd.Flags().StringVar(&enrollToken, "enroll-token", "", "shared token agents use to enroll (WARNING: visible in process list; prefer --enroll-token-env)")
	cmd.Flags().StringVar(&enrollTokenEnv, "enroll-token-env", "", "name of the environment variable holding the enrollment token")
	cmd.Flags().StringVar(&authPath, "auth-config", "", "YAML file with API bearer tokens and roles (default: no authentication)")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "TLS certificate file (requires --tls-key)")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "TLS private key file (requires --tls-cert)")
	cmd.Flags().StringVar(&webhookURL, "webhook-url", "", "POST drift notifications to this URL")
	return cmd
}

// applyAuth loads and installs the auth configuration when a path is given.
func applyAuth(srv *server.Server, path string) error {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading auth config: %w", err)
	}
	cfg, err := server.LoadAuthConfig(data)
	if err != nil {
		return err
	}
	srv.SetAuth(cfg)
	return nil
}

func init() {
	rootCmd.AddCommand(newServerCmd())
}
