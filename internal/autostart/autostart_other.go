//go:build !windows

package autostart

func Enable(string, string) error { return ErrUnsupported }

func Disable(string) error { return nil }

func Command(string) string { return "" }
