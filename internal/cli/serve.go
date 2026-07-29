package cli

import (
	"fmt"

	"github.com/kurtserdar/hsm-doctor/internal/server"
	"github.com/kurtserdar/hsm-doctor/internal/store"
	"github.com/kurtserdar/hsm-doctor/internal/version"
	"github.com/spf13/cobra"
)

func newServeCmd() *cobra.Command {
	var conn connFlags
	var listen, rulesPath, dbPath string
	var noDB bool

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the local web interface and REST API",
		Long: `Starts a local HTTP server exposing HSM Doctor's functionality as a
REST API under /api/v1 plus the embedded web interface.

The server is meant for local, single-operator use: it binds to loopback by
default and the PIN is taken once at startup (prefer --pin-env), never per
request and never logged. Think twice before exposing it beyond localhost.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadRules(rulesPath)
			if err != nil {
				return err
			}
			pin, err := conn.resolvePIN(true)
			if err != nil {
				return err
			}
			if pin == "" {
				fmt.Fprintln(cmd.ErrOrStderr(), "Warning: no PIN provided; scans will only see public objects.")
			}

			var st store.Store
			if !noDB {
				if dbPath == "" {
					if dbPath, err = store.DefaultPath(); err != nil {
						return err
					}
				}
				db, err := store.Open(dbPath)
				if err != nil {
					return err
				}
				st = db
				fmt.Fprintf(cmd.ErrOrStderr(), "Scan history database: %s\n", dbPath)
			}

			srv, err := server.New(conn.module, pin, cfg, version.Version, st)
			if err != nil {
				if st != nil {
					_ = st.Close()
				}
				return err
			}
			defer srv.Close()
			return srv.ListenAndServe(listen)
		},
	}
	// serve needs the module but not a fixed slot: slots are chosen per API call.
	cmd.Flags().StringVar(&conn.module, "module", "", "path to the PKCS#11 library (required)")
	_ = cmd.MarkFlagRequired("module")
	cmd.Flags().StringVar(&conn.pin, "pin", "", "user PIN (WARNING: visible in shell history; prefer --pin-env)")
	cmd.Flags().StringVar(&conn.pinEnv, "pin-env", "", "name of the environment variable holding the user PIN")
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:8080", "listen address")
	cmd.Flags().StringVar(&rulesPath, "rules", "", "path to a custom rules YAML file (default: built-in rules)")
	cmd.Flags().StringVar(&dbPath, "db", "", "scan history database path (default: ~/.local/share/hsmdoctor/hsmdoctor.db)")
	cmd.Flags().BoolVar(&noDB, "no-db", false, "disable scan history persistence")
	return cmd
}

func init() {
	rootCmd.AddCommand(newServeCmd())
}
