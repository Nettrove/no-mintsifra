//go:build !windows

package sysproxy

func Current() (string, error) { return "", ErrUnsupported }

func ReadManual() (Manual, error) { return Manual{}, ErrUnsupported }

func Set(string) (State, error) { return State{}, ErrUnsupported }

func Restore(string, State) error { return ErrUnsupported }
