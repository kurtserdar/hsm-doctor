package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/vendors"
	"github.com/spf13/cobra"
)

func newVendorCmd() *cobra.Command {
	var conn connFlags
	var vendorConfig string
	var asJSON, list bool

	cmd := &cobra.Command{
		Use:   "vendor",
		Short: "Collect vendor appliance health for a token",
		Long: `Detects the HSM vendor behind a token and collects appliance-level
health that PKCS#11 cannot expose: device resources, HA status, partition
utilization, tamper and backup state.

Some providers are experimental and have not been validated against real
hardware; their output is labeled accordingly. List providers with --list.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if list {
				printProviders(cmd)
				return nil
			}

			client, slot, _, err := conn.connect(true, false)
			if err != nil {
				return err
			}
			defer client.Close()

			module, err := client.Info()
			if err != nil {
				return err
			}
			var token *p11.TokenInfo
			slots, err := client.Slots()
			if err != nil {
				return err
			}
			for _, s := range slots {
				if s.ID == slot {
					token = s.Token
					break
				}
			}

			provider := vendor.Detect(module, token)
			if provider == nil {
				return fmt.Errorf("no vendor provider recognized this module (manufacturer %q); see --list", module.Manufacturer)
			}
			vcfg, err := loadVendorConfig(vendorConfig)
			if err != nil {
				return err
			}
			info, err := provider.Collect(cmd.Context(), vcfg.For(provider.Name()))
			if err != nil {
				return err
			}

			if asJSON {
				return jsonEncoder(cmd.OutOrStdout()).Encode(info)
			}
			printVendorInfo(cmd, info)
			return nil
		},
	}
	conn.register(cmd, true)
	cmd.Flags().StringVar(&vendorConfig, "vendor-config", "", "vendor configuration file")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	cmd.Flags().BoolVar(&list, "list", false, "list available vendor providers and exit")
	return cmd
}

func printProviders(cmd *cobra.Command) {
	out := cmd.OutOrStdout()
	names := vendor.Names()
	sort.Strings(names)
	fmt.Fprintln(out, "Available vendor providers:")
	for _, n := range names {
		fmt.Fprintf(out, "  %s\n", n)
	}
}

func printVendorInfo(cmd *cobra.Command, info *vendor.Info) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Vendor: %s", info.Provider)
	if info.Experimental {
		fmt.Fprint(out, "  [experimental — not validated on real hardware]")
	}
	fmt.Fprint(out, "\n\n")

	if d := info.Device; d != nil {
		fmt.Fprintln(out, "Device:")
		printFloat(out, "  CPU", d.CPUPercent, "%")
		printFloat(out, "  Memory", d.MemoryPercent, "%")
		printFloat(out, "  Disk", d.DiskPercent, "%")
		printFloat(out, "  Temperature", d.TemperatureC, "°C")
	}
	if ha := info.HA; ha != nil {
		fmt.Fprintf(out, "HA group %s:\n", ha.Group)
		for _, m := range ha.Members {
			state := "down"
			if m.Up {
				state = "up"
			}
			fmt.Fprintf(out, "  %-24s %s (%s)\n", m.Name, state, m.Status)
		}
	}
	if len(info.Partitions) > 0 {
		fmt.Fprintln(out, "Partitions:")
		for _, p := range info.Partitions {
			line := "  " + p.Label
			if p.UsedObjects != nil {
				line += fmt.Sprintf("  objects=%d", *p.UsedObjects)
			}
			if p.UsedStorageBytes != nil {
				line += fmt.Sprintf("  storage=%d bytes", *p.UsedStorageBytes)
			}
			fmt.Fprintln(out, line)
		}
	}
	if t := info.Tamper; t != nil {
		state := "clear"
		if t.Tampered {
			state = "TAMPERED"
		}
		fmt.Fprintf(out, "Tamper: %s %s\n", state, t.Detail)
	}
	if len(info.Extra) > 0 {
		fmt.Fprintln(out, "Details:")
		keys := make([]string, 0, len(info.Extra))
		for k := range info.Extra {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(out, "  %-16s %s\n", k, info.Extra[k])
		}
	}
	if len(info.Findings) > 0 {
		fmt.Fprintln(out, "\nFindings:")
		for _, f := range info.Findings {
			fmt.Fprintf(out, "  [%s] %s (%s)\n", f.RuleID, f.Title, strings.ToUpper(string(f.Severity)))
			if f.Detail != "" {
				fmt.Fprintf(out, "        %s\n", f.Detail)
			}
		}
	}
}

func printFloat(out interface{ Write([]byte) (int, error) }, label string, v *float64, unit string) {
	if v != nil {
		fmt.Fprintf(out, "%s: %.1f%s\n", label, *v, unit)
	}
}

func init() {
	rootCmd.AddCommand(newVendorCmd())
}
