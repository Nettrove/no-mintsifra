// Package sysproxy points the current user's Windows proxy settings at a PAC
// URL and puts back whatever was there before.
package sysproxy

import "errors"

var ErrUnsupported = errors.New("sysproxy: only available on Windows")

// State is what the user had configured before the PAC URL was set.
type State struct {
	AutoConfigURL string `json:"autoConfigURL"`
	HadURL        bool   `json:"hadURL"`
}
