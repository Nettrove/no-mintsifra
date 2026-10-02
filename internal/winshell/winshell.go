// Package winshell wraps the few Windows shell features the tool needs:
// process inspection, a console, message boxes, shortcuts and deferred removal.
package winshell

import "errors"

var ErrUnsupported = errors.New("winshell: only available on Windows")

type Process struct {
	PID         int
	CommandLine string
}

type Shortcut struct {
	Path        string
	Target      string
	Args        string
	Icon        string
	Description string
}
