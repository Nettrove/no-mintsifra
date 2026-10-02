//go:build windows

package appentry

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

const uninstallKey = `Software\Microsoft\Windows\CurrentVersion\Uninstall\`

// Register writes the entry under id, replacing an older one.
func Register(id string, e Entry) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, uninstallKey+id, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	for name, value := range map[string]string{
		"DisplayName":     e.Name,
		"DisplayVersion":  e.Version,
		"Publisher":       e.Publisher,
		"DisplayIcon":     e.Icon,
		"InstallLocation": e.InstallLocation,
		"UninstallString": e.UninstallString,
	} {
		if err := k.SetStringValue(name, value); err != nil {
			return err
		}
	}
	for _, name := range []string{"NoModify", "NoRepair"} {
		if err := k.SetDWordValue(name, 1); err != nil {
			return err
		}
	}
	return nil
}

func Unregister(id string) error {
	err := registry.DeleteKey(registry.CURRENT_USER, uninstallKey+id)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	return err
}
