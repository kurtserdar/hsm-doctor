package cli

import (
	"fmt"

	"github.com/kurtserdar/hsm-doctor/internal/server"
	"github.com/kurtserdar/hsm-doctor/internal/store"
	"github.com/kurtserdar/hsm-doctor/internal/version"
	"github.com/robfig/cron/v3"
	"github.com/spf13/cobra"
)

func newServeCmd() *cobra.Command {
	var conn connFlags
	var listen, rulesPath, dbPath string
	var packNames []string
	var authPath, tlsCert, tlsKey, clientCA string
	var webhookURL, schedule, vendorConfig string
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
			cfg, err := resolveRuleConfig(rulesPath, packNames)
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
				resolved, err := resolveDBPath(dbPath)
				if err != nil {
					return err
				}
				db, err := store.Open(resolved)
				if err != nil {
					return err
				}
				st = db
				fmt.Fprintf(cmd.ErrOrStderr(), "Scan history database: %s\n", store.Redact(resolved))
			}

			srv, err := server.New(conn.module, pin, cfg, version.Version, st)
			if err != nil {
				if st != nil {
					_ = st.Close()
				}
				return err
			}
			defer srv.Close()
			if err := applyAuth(srv, authPath); err != nil {
				return err
			}
			srv.SetWebhook(webhookURL)

			if vcfg, err := loadVendorConfig(vendorConfig); err != nil {
				return err
			} else if vcfg != nil {
				srv.SetVendorConfig(vcfg)
			}

			if schedule != "" {
				c := cron.New()
				_, err := c.AddFunc(schedule, func() {
					slots, err := srv.TokenSlots()
					if err != nil {
						fmt.Fprintf(cmd.ErrOrStderr(), "scheduled scan: %v\n", err)
						return
					}
					for _, id := range slots {
						if _, err := srv.ScanSlot(id); err != nil {
							fmt.Fprintf(cmd.ErrOrStderr(), "scheduled scan of slot %d: %v\n", id, err)
						}
					}
				})
				if err != nil {
					return fmt.Errorf("invalid --schedule expression: %w", err)
				}
				c.Start()
				defer c.Stop()
				fmt.Fprintf(cmd.ErrOrStderr(), "Scheduled scans enabled: %q\n", schedule)
			}

			return srv.ListenAndServe(listen, server.TLSOptions{
				CertFile: tlsCert, KeyFile: tlsKey, ClientCAFile: clientCA,
			})
		},
	}
	// serve needs the module but not a fixed slot: slots are chosen per API call.
	cmd.Flags().StringVar(&conn.module, "module", "", "path to the PKCS#11 library (required)")
	_ = cmd.MarkFlagRequired("module")
	cmd.Flags().StringVar(&conn.pin, "pin", "", "user PIN (WARNING: visible in shell history; prefer --pin-env)")
	cmd.Flags().StringVar(&conn.pinEnv, "pin-env", "", "name of the environment variable holding the user PIN")
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:8080", "listen address")
	cmd.Flags().StringVar(&rulesPath, "rules", "", "path to a custom rules YAML file replacing all packs")
	cmd.Flags().StringArrayVar(&packNames, "pack", nil, "policy pack to apply (embedded name or file path; repeatable)")
	cmd.Flags().StringVar(&dbPath, "db", "", "SQLite path or postgres:// DSN (default: ~/.local/share/hsmdoctor/hsmdoctor.db; or HSMDOCTOR_DB)")
	cmd.Flags().BoolVar(&noDB, "no-db", false, "disable scan history persistence")
	cmd.Flags().StringVar(&authPath, "auth-config", "", "YAML file with API bearer tokens and roles (default: no authentication)")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "TLS certificate file (requires --tls-key)")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "TLS private key file (requires --tls-cert)")
	cmd.Flags().StringVar(&clientCA, "client-ca", "", "require client certificates signed by this CA (mutual TLS; requires --tls-cert/--tls-key)")
	cmd.Flags().StringVar(&webhookURL, "webhook-url", "", "POST drift notifications to this URL")
	cmd.Flags().StringVar(&schedule, "schedule", "", `cron expression for automatic scans of all tokens (e.g. "0 */6 * * *")`)
	cmd.Flags().StringVar(&vendorConfig, "vendor-config", "", "vendor configuration file enabling appliance-level checks")
	return cmd
}

func init() {
	rootCmd.AddCommand(newServeCmd())
}
