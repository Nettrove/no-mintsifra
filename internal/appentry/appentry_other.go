//go:build !windows

package appentry

func Register(string, Entry) error { return ErrUnsupported }

func Unregister(string) error { return nil }
