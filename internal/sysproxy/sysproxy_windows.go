//go:build windows

package sysproxy

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	settingsKey           = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	optionSettingsChanged = 39
	optionRefresh         = 37
)

var internetSetOption = windows.NewLazySystemDLL("wininet.dll").NewProc("InternetSetOptionW")

// Current returns the PAC URL that is configured now, if any.
func Current() (string, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, settingsKey, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue("AutoConfigURL")
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	return v, err
}

// ReadManual returns the user's manual proxy, which stays in the registry
// and keeps being edited by VPN clients while a PAC URL is set.
func ReadManual() (Manual, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, settingsKey, registry.QUERY_VALUE)
	if err != nil {
		return Manual{}, err
	}
	defer k.Close()
	enabled, _, _ := k.GetIntegerValue("ProxyEnable")
	server, _, _ := k.GetStringValue("ProxyServer")
	override, _, _ := k.GetStringValue("ProxyOverride")
	return Manual{Enabled: enabled != 0, Server: strings.TrimSpace(server), Override: splitOverride(override)}, nil
}

// Set installs url as the PAC URL and returns what it replaced.
func Set(url string) (State, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, settingsKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return State{}, err
	}
	defer k.Close()
	var prev State
	if v, _, err := k.GetStringValue("AutoConfigURL"); err == nil {
		prev = State{AutoConfigURL: v, HadURL: true}
	}
	if err := k.SetStringValue("AutoConfigURL", url); err != nil {
		return State{}, err
	}
	notify()
	return prev, nil
}

// Restore puts back prev, but only while url is still the configured value,
// so a change the user made later is left alone.
func Restore(url string, prev State) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, settingsKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if v, _, err := k.GetStringValue("AutoConfigURL"); err != nil || v != url {
		return nil
	}
	if prev.HadURL {
		err = k.SetStringValue("AutoConfigURL", prev.AutoConfigURL)
	} else {
		err = k.DeleteValue("AutoConfigURL")
	}
	notify()
	return err
}

// notify tells running WinINet clients to reload the settings.
func notify() {
	_, _, _ = internetSetOption.Call(0, optionSettingsChanged, 0, 0)
	_, _, _ = internetSetOption.Call(0, optionRefresh, 0, 0)
}
