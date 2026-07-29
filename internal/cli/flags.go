package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
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
// PKCS#11 module. Tokens are addressed either with --module/--slot or with
// an RFC 7512 PKCS#11 URI.
type connFlags struct {
	module string
	slot   uint
	pin    string
	pinEnv string
	uri    string
	cmd    *cobra.Command
}

func (f *connFlags) register(cmd *cobra.Command, needsSlot bool) {
	f.cmd = cmd
	cmd.Flags().StringVar(&f.module, "module", "", "path to the PKCS#11 library")
	cmd.Flags().StringVar(&f.uri, "uri", "", `RFC 7512 PKCS#11 URI, e.g. "pkcs11:token=PROD?module-path=/usr/lib/libpkcs11.so"`)
	if needsSlot {
		cmd.Flags().UintVar(&f.slot, "slot", 0, "slot ID to operate on")
		cmd.Flags().StringVar(&f.pin, "pin", "", "user PIN (WARNING: visible in shell history; prefer --pin-env)")
		cmd.Flags().StringVar(&f.pinEnv, "pin-env", "", "name of the environment variable holding the user PIN")
	}
}

// connect opens the module and resolves the target slot and PIN from the
// flags and/or the PKCS#11 URI. Precedence: explicit flags beat URI
// attributes; the interactive prompt is the last resort for the PIN.
func (f *connFlags) connect(needSlot, promptPIN bool) (*p11.Client, uint, string, error) {
	var parsed *p11.URI
	if f.uri != "" {
		var err error
		if parsed, err = p11.ParseURI(f.uri); err != nil {
			return nil, 0, "", err
		}
	}

	module := f.module
	if module == "" && parsed != nil {
		module = parsed.ModulePath
	}
	if module == "" {
		return nil, 0, "", fmt.Errorf("no PKCS#11 module: use --module or a --uri with module-path")
	}

	pin, err := f.resolvePIN(false)
	if err != nil {
		return nil, 0, "", err
	}
	if pin == "" && parsed != nil {
		if pin, err = parsed.PIN(); err != nil {
			return nil, 0, "", err
		}
	}
	if pin == "" && promptPIN {
		if pin, err = promptForPIN(); err != nil {
			return nil, 0, "", err
		}
	}

	client, err := p11.Open(module)
	if err != nil {
		return nil, 0, "", err
	}

	var slot uint
	if needSlot {
		switch {
		case f.cmd != nil && f.cmd.Flags().Changed("slot"):
			slot = f.slot
		case parsed != nil:
			slots, err := client.Slots()
			if err != nil {
				client.Close()
				return nil, 0, "", err
			}
			if slot, err = parsed.MatchSlot(slots); err != nil {
				client.Close()
				return nil, 0, "", err
			}
		default:
			client.Close()
			return nil, 0, "", fmt.Errorf("no target token: use --slot or a --uri identifying the token")
		}
	}
	return client, slot, pin, nil
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
	if prompt {
		return promptForPIN()
	}
	return "", nil
}

// promptForPIN asks for the PIN on the terminal; returns empty when stdin
// is not a terminal (e.g. cron).
func promptForPIN() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", nil
	}
	fmt.Fprint(os.Stderr, "User PIN (empty for public-only access): ")
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading PIN: %w", err)
	}
	return string(raw), nil
}
