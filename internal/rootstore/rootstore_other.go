//go:build !windows

package rootstore

func Install([]byte) error { return ErrUnsupported }

func Installed([]byte) bool { return false }

func Remove(string, []byte) (int, error) { return 0, nil }
