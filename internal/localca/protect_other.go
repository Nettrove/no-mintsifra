//go:build !windows

package localca

// Outside Windows the key relies on the 0600 file mode alone.
func protect(data []byte) ([]byte, error) { return data, nil }

func unprotect(data []byte) ([]byte, error) { return data, nil }
