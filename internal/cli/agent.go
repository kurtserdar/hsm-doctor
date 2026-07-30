package cli

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kurtserdar/hsm-doctor/internal/agent"
	"github.com/kurtserdar/hsm-doctor/internal/policy"
	"github.com/kurtserdar/hsm-doctor/internal/version"
	"github.com/spf13/cobra"
)

func newAgentCmd() *cobra.Command {
	var conn connFlags
	var serverURL, name, enrollToken, enrollTokenEnv, tokenFile, rulesPath, vendorConfig string
	var clientCert, clientKey, serverCA string
	var packNames []string
	var interval time.Duration
	var slotSet bool
	var slot uint
	var once bool

	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Continuously scan local tokens and push reports to a central server",
		Long: `Runs on a host with the vendor PKCS#11 client installed. Scans all
token-bearing slots (or one specific --slot) on an interval and pushes the
reports to a central HSM Doctor server.

The PIN never leaves this host; only finished reports (metadata, findings,
scores) are transmitted. On first run the agent enrolls using the shared
enrollment token and stores its permanent token in --token-file.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			slotSet = cmd.Flags().Changed("slot")

			if name == "" {
				host, err := os.Hostname()
				if err != nil {
					return fmt.Errorf("cannot determine hostname; use --name: %w", err)
				}
				name = host
			}
			if tokenFile == "" {
				dir, err := dataDir()
				if err != nil {
					return err
				}
				tokenFile = filepath.Join(dir, "agent.token")
			}

			httpc, err := agent.NewHTTPClient(agent.TLSOptions{
				ClientCertFile: clientCert, ClientKeyFile: clientKey, ServerCAFile: serverCA,
			})
			if err != nil {
				return err
			}

			token, err := loadOrEnroll(cmd, httpc, serverURL, name, enrollToken, enrollTokenEnv, tokenFile)
			if err != nil {
				return err
			}
			client := &agent.Client{ServerURL: strings.TrimRight(serverURL, "/"), Token: token, HTTP: httpc}

			cfg, err := resolveRuleConfig(rulesPath, packNames)
			if err != nil {
				return err
			}
			pin, err := conn.resolvePIN(!once)
			if err != nil {
				return err
			}

			vcfg, err := loadVendorConfig(vendorConfig)
			if err != nil {
				return err
			}
			vendorFn := vendorCollector(cmd.ErrOrStderr(), vcfg)

			var slotPtr *uint
			if slotSet {
				slotPtr = &slot
			}

			for {
				pushed, err := scanAndPush(cmd, client, conn.module, pin, slotPtr, cfg, vendorFn)
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "Error: %v\n", err)
					if once {
						return err
					}
				} else {
					fmt.Fprintf(cmd.ErrOrStderr(), "%s pushed %d report(s)\n",
						time.Now().Format(time.RFC3339), pushed)
				}
				if once {
					return nil
				}
				time.Sleep(interval)
			}
		},
	}
	cmd.Flags().StringVar(&conn.module, "module", "", "path to the PKCS#11 library (required)")
	_ = cmd.MarkFlagRequired("module")
	cmd.Flags().UintVar(&slot, "slot", 0, "scan only this slot (default: all slots with tokens)")
	cmd.Flags().StringVar(&conn.pin, "pin", "", "user PIN (WARNING: visible in shell history; prefer --pin-env)")
	cmd.Flags().StringVar(&conn.pinEnv, "pin-env", "", "name of the environment variable holding the user PIN")
	cmd.Flags().StringVar(&serverURL, "server", "", "central server base URL, e.g. https://hsmdoctor.example.com (required)")
	_ = cmd.MarkFlagRequired("server")
	cmd.Flags().StringVar(&name, "name", "", "agent name (default: hostname)")
	cmd.Flags().StringVar(&enrollToken, "enroll-token", "", "enrollment token for first registration (prefer --enroll-token-env)")
	cmd.Flags().StringVar(&enrollTokenEnv, "enroll-token-env", "", "name of the environment variable holding the enrollment token")
	cmd.Flags().StringVar(&tokenFile, "token-file", "", "file storing the permanent agent token (default: ~/.local/share/hsmdoctor/agent.token)")
	cmd.Flags().DurationVar(&interval, "interval", 15*time.Minute, "time between scans")
	cmd.Flags().BoolVar(&once, "once", false, "scan and push once, then exit (for cron)")
	cmd.Flags().StringVar(&rulesPath, "rules", "", "path to a custom rules YAML file replacing all packs")
	cmd.Flags().StringArrayVar(&packNames, "pack", nil, "policy pack to apply (embedded name or file path; repeatable)")
	cmd.Flags().StringVar(&vendorConfig, "vendor-config", "", "vendor configuration file enabling appliance-level checks")
	cmd.Flags().StringVar(&clientCert, "tls-client-cert", "", "client certificate for mutual TLS to the server")
	cmd.Flags().StringVar(&clientKey, "tls-client-key", "", "client private key for mutual TLS (requires --tls-client-cert)")
	cmd.Flags().StringVar(&serverCA, "server-ca", "", "trust this CA for the server's certificate instead of the system roots")
	return cmd
}

// dataDir returns the hsmdoctor data directory, creating it if needed.
func dataDir() (string, error) {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolving home directory: %w", err)
		}
		base = filepath.Join(home, ".local", "share")
	}
	dir := filepath.Join(base, "hsmdoctor")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// loadOrEnroll returns the stored agent token or performs first-time
// enrollment (over httpc, so mTLS applies) and persists the result.
func loadOrEnroll(cmd *cobra.Command, httpc *http.Client, serverURL, name, enrollToken, enrollTokenEnv, tokenFile string) (string, error) {
	if data, err := os.ReadFile(tokenFile); err == nil {
		token := strings.TrimSpace(string(data))
		if token != "" {
			return token, nil
		}
	}

	if enrollToken == "" && enrollTokenEnv != "" {
		enrollToken = os.Getenv(enrollTokenEnv)
	}
	if enrollToken == "" {
		return "", fmt.Errorf("no agent token at %s and no enrollment token provided (--enroll-token-env)", tokenFile)
	}
	token, err := agent.Enroll(httpc, strings.TrimRight(serverURL, "/"), name, enrollToken)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("storing agent token: %w", err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Enrolled as %q; token stored in %s\n", name, tokenFile)
	return token, nil
}

func init() {
	rootCmd.AddCommand(newAgentCmd())
}

func scanAndPush(cmd *cobra.Command, client *agent.Client, module, pin string, slot *uint, cfg *policy.Config, vendorFn agent.VendorCollector) (int, error) {
	reports, collectErr := agent.CollectReports(module, pin, slot, cfg, version.Version, vendorFn)
	// Push whatever was collected even when some slots failed.
	pushed := 0
	for _, rep := range reports {
		if err := client.Push(rep); err != nil {
			return pushed, err
		}
		pushed++
	}
	return pushed, collectErr
}
