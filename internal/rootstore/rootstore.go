// Package rootstore adds and removes the local CA in the current user's
// Trusted Root store. Windows itself asks the user to confirm both.
package rootstore

import "errors"

var (
	ErrUnsupported = errors.New("rootstore: only available on Windows")
	// ErrDeclined means the user answered No in the Windows confirmation.
	ErrDeclined = errors.New("rootstore: declined in the Windows confirmation")
)
