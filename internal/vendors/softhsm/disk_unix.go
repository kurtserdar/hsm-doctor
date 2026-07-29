//go:build !windows

package softhsm

import "syscall"

// diskUsedPercent reports how full the filesystem holding path is.
func diskUsedPercent(path string) (float64, bool) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil || stat.Blocks == 0 {
		return 0, false
	}
	return 100 * (1 - float64(stat.Bavail)/float64(stat.Blocks)), true
}
