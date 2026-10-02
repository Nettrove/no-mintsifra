// Package autostart starts the proxy when the user signs in to Windows.
package autostart

import "errors"

var ErrUnsupported = errors.New("autostart: only available on Windows")
