// hsmdoctor is a vendor-neutral CLI for HSM health checks, security posture
// assessment and PKCS#11 diagnostics.
package main

import "github.com/kurtserdar/hsm-doctor/internal/cli"

func main() {
	cli.Execute()
}
