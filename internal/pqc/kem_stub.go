//go:build !cgo || windows

package pqc

// kemRoundTrip is unavailable without cgo (it needs dlopen + the PKCS#11 3.2
// interface) and on Windows, so ML-KEM stays a key-generation-only probe
// there. The signature mirrors the cgo implementation.
func kemRoundTrip(modulePath string, session, pub, priv uint64, mech uint) (uint64, uint64, error) {
	return 0, 0, errKEMUnsupported
}
