// Package appentry lists the program under Settings > Apps for the current
// user, so it can be removed the way any other program is.
package appentry

import "errors"

var ErrUnsupported = errors.New("appentry: only available on Windows")

type Entry struct {
	Name            string
	Version         string
	Publisher       string
	Icon            string
	InstallLocation string
	UninstallString string
}
