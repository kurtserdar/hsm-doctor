package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/spf13/cobra"
)

type discoverResult struct {
	Module     p11.ModuleInfo           `json:"module"`
	Slots      []p11.SlotInfo           `json:"slots"`
	Mechanisms map[uint][]p11.Mechanism `json:"mechanisms,omitempty"`
}

func newDiscoverCmd() *cobra.Command {
	var conn connFlags
	var showMechs bool
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover slots, tokens and mechanisms of a PKCS#11 module",
		Long: `Loads a PKCS#11 library, lists its slots and tokens, and optionally the
mechanisms supported by each token. No login is required.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, _, _, err := conn.connect(false, false)
			if err != nil {
				return err
			}
			defer client.Close()

			res := discoverResult{}
			if res.Module, err = client.Info(); err != nil {
				return err
			}
			if res.Slots, err = client.Slots(); err != nil {
				return err
			}
			if showMechs {
				res.Mechanisms = map[uint][]p11.Mechanism{}
				for _, s := range res.Slots {
					if !s.TokenPresent {
						continue
					}
					mechs, err := client.Mechanisms(s.ID)
					if err != nil {
						return err
					}
					res.Mechanisms[s.ID] = mechs
				}
			}

			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}
			printDiscover(res)
			return nil
		},
	}
	conn.register(cmd, false)
	cmd.Flags().BoolVar(&showMechs, "mechanisms", false, "list mechanisms supported by each token")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return cmd
}

func printDiscover(res discoverResult) {
	m := res.Module
	fmt.Printf("Module:  %s\n", m.Path)
	fmt.Printf("  Description:      %s\n", m.Description)
	fmt.Printf("  Manufacturer:     %s\n", m.Manufacturer)
	fmt.Printf("  Cryptoki version: %s\n", m.CryptokiVersion)
	fmt.Printf("  Library version:  %s\n", m.LibraryVersion)

	if len(res.Slots) == 0 {
		fmt.Println("\nNo slots found.")
		return
	}
	for _, s := range res.Slots {
		fmt.Printf("\nSlot %d (0x%x)\n", s.ID, s.ID)
		fmt.Printf("  Description:  %s\n", s.Description)
		if !s.TokenPresent {
			fmt.Println("  Token:        (not present)")
			continue
		}
		t := s.Token
		fmt.Printf("  Token:        %s\n", t.Label)
		fmt.Printf("    Manufacturer:   %s\n", t.Manufacturer)
		fmt.Printf("    Model:          %s\n", t.Model)
		fmt.Printf("    Serial:         %s\n", t.SerialNumber)
		fmt.Printf("    Firmware:       %s\n", t.FirmwareVersion)
		fmt.Printf("    Initialized:    %v\n", t.Initialized)
		fmt.Printf("    Login required: %v\n", t.LoginRequired)
		if res.Mechanisms != nil {
			mechs := res.Mechanisms[s.ID]
			fmt.Printf("    Mechanisms:     %d\n", len(mechs))
			for _, mech := range mechs {
				line := fmt.Sprintf("      %-38s", mech.Name)
				if mech.MinKeySize > 0 || mech.MaxKeySize > 0 {
					line += fmt.Sprintf(" %5d..%-5d", mech.MinKeySize, mech.MaxKeySize)
				}
				fmt.Println(line)
			}
		}
	}
}

func init() {
	rootCmd.AddCommand(newDiscoverCmd())
}
