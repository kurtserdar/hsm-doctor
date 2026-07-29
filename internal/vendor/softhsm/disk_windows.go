//go:build windows

package softhsm

// diskUsedPercent is not implemented on Windows; the disk-usage finding is
// simply skipped there.
func diskUsedPercent(path string) (float64, bool) {
	return 0, false
}
