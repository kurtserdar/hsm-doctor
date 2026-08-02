package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/kurtserdar/hsm-doctor/internal/p11"
	"github.com/kurtserdar/hsm-doctor/internal/vendors"

	// Register the built-in vendor providers.
	_ "github.com/kurtserdar/hsm-doctor/internal/vendors/azurehsm"
	_ "github.com/kurtserdar/hsm-doctor/internal/vendors/bouncyhsm"
	_ "github.com/kurtserdar/hsm-doctor/internal/vendors/cloudhsm"
	_ "github.com/kurtserdar/hsm-doctor/internal/vendors/gcp"
	_ "github.com/kurtserdar/hsm-doctor/internal/vendors/luna"
	_ "github.com/kurtserdar/hsm-doctor/internal/vendors/nshield"
	_ "github.com/kurtserdar/hsm-doctor/internal/vendors/softhsm"
)

// collectVendor detects the vendor for a module/token and collects its
// information. It returns (nil, nil) when no provider matches or the
// matching provider needs configuration that was not supplied, so callers
// can treat vendor data as optional enrichment.
func collectVendor(ctx context.Context, warn io.Writer, cfgFile *vendor.File, module p11.ModuleInfo, token *p11.TokenInfo) *vendor.Info {
	provider := vendor.Detect(module, token)
	if provider == nil {
		return nil
	}
	info, err := provider.Collect(ctx, cfgFile.For(provider.Name()))
	if err != nil {
		if errors.Is(err, vendor.ErrNotConfigured) {
			fmt.Fprintf(warn, "Vendor provider %q detected but not configured; pass --vendor-config to enable it.\n", provider.Name())
			return nil
		}
		fmt.Fprintf(warn, "Vendor provider %q failed: %v\n", provider.Name(), err)
		return nil
	}
	return info
}

// loadVendorConfig loads the vendor config file when a path is given.
func loadVendorConfig(path string) (*vendor.File, error) {
	if path == "" {
		return nil, nil
	}
	return vendor.LoadConfigFile(path)
}

// vendorCollector builds an agent.VendorCollector from a config file, or
// nil when no config was supplied. Errors are logged and yield no vendor
// data, so a vendor hiccup never blocks the agent's core scan.
func vendorCollector(warn io.Writer, cfgFile *vendor.File) func(p11.ModuleInfo, *p11.TokenInfo) *vendor.Info {
	if cfgFile == nil {
		return nil
	}
	return func(module p11.ModuleInfo, token *p11.TokenInfo) *vendor.Info {
		return collectVendor(context.Background(), warn, cfgFile, module, token)
	}
}
