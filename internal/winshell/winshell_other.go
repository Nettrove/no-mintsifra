//go:build !windows

package winshell

import "runtime"

func Processes(string) ([]Process, error) { return nil, ErrUnsupported }

func StartDetached(string, ...string) error { return ErrUnsupported }

func RunElevated(string, ...string) error { return ErrUnsupported }

func Close([]int) {}

func Kill([]int) {}

func Notify(string, string) {}

func RemoveLater(string) error { return ErrUnsupported }

func OpenConsole(string) (available, created bool) { return true, false }

func OSVersion() string { return runtime.GOOS }

func DocumentsDir() (string, error) { return "", ErrUnsupported }

func StartMenuDir() (string, error) { return "", ErrUnsupported }

func CreateShortcut(Shortcut) error { return ErrUnsupported }
