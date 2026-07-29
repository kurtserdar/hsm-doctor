package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// jsonEncoder returns an indenting JSON encoder for CLI output.
func jsonEncoder(w io.Writer) *json.Encoder {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc
}

// connFlags holds the connection options shared by commands that talk to a
// PKCS#11 module.
type connFlags struct {
	module string
	slot   uint
	pin    string
	pinEnv string
}

func (f *connFlags) register(cmd *cobra.Command, needsSlot bool) {
	cmd.Flags().StringVar(&f.module, "module", "", "path to the PKCS#11 library (required)")
	_ = cmd.MarkFlagRequired("module")
	if needsSlot {
		cmd.Flags().UintVar(&f.slot, "slot", 0, "slot ID to operate on (required)")
		_ = cmd.MarkFlagRequired("slot")
		cmd.Flags().StringVar(&f.pin, "pin", "", "user PIN (WARNING: visible in shell history; prefer --pin-env)")
		cmd.Flags().StringVar(&f.pinEnv, "pin-env", "", "name of the environment variable holding the user PIN")
	}
}

// resolvePIN returns the PIN from --pin, --pin-env or an interactive prompt,
// in that order. An empty result means "connect without logging in".
func (f *connFlags) resolvePIN(prompt bool) (string, error) {
	if f.pin != "" {
		return f.pin, nil
	}
	if f.pinEnv != "" {
		pin := os.Getenv(f.pinEnv)
		if pin == "" {
			return "", fmt.Errorf("environment variable %s is empty or not set", f.pinEnv)
		}
		return pin, nil
	}
	if prompt && term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "User PIN (empty for public-only access): ")
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("reading PIN: %w", err)
		}
		return string(raw), nil
	}
	return "", nil
}
