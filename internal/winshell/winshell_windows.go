//go:build windows

package winshell

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const createNoWindow = 0x08000000

func powershellCmd(script string, env ...string) *exec.Cmd {
	full := "[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ErrorActionPreference='Stop';" + script
	units := utf16.Encode([]rune(full))
	raw := make([]byte, 0, len(units)*2)
	for _, u := range units {
		raw = append(raw, byte(u), byte(u>>8))
	}

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", base64.StdEncoding.EncodeToString(raw))
	cmd.Env = append(os.Environ(), env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd
}

func powershell(script string, env ...string) ([]byte, error) {
	cmd := powershellCmd(script, env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("powershell: %w: %s", err, bytes.TrimSpace(stderr.Bytes()))
	}
	return out, nil
}

// Processes lists running processes whose image is exe.
func Processes(exe string) ([]Process, error) {
	script := `Get-CimInstance Win32_Process -Filter ("Name='" + $env:NM_NAME + "'") |` +
		` Where-Object { $_.ExecutablePath -eq $env:NM_EXE } |` +
		` ForEach-Object { [pscustomobject]@{ PID = [int]$_.ProcessId; CommandLine = [string]$_.CommandLine } } |` +
		` ConvertTo-Json -Compress`
	out, err := powershell(script, "NM_NAME="+filepath.Base(exe), "NM_EXE="+exe)
	if err != nil {
		return nil, err
	}
	return parseProcesses(out)
}

// Windows PowerShell 5.1 emits a bare object for one match and nothing for none.
func parseProcesses(out []byte) ([]Process, error) {
	out = bytes.TrimSpace(out)
	switch {
	case len(out) == 0:
		return nil, nil
	case out[0] == '{':
		out = append(append([]byte{'['}, out...), ']')
	}
	var procs []Process
	if err := json.Unmarshal(out, &procs); err != nil {
		return nil, fmt.Errorf("winshell: parse process list: %w", err)
	}
	return procs, nil
}

// StartDetached starts exe in the background without a console window.
func StartDetached(exe string, args ...string) error {
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// RunElevated starts exe with args as administrator, which shows the UAC
// prompt, and waits for it to exit.
func RunElevated(exe string, args ...string) error {
	_, err := powershell(`$p = Start-Process -FilePath $env:NM_EXE -ArgumentList $env:NM_ARGS -Verb RunAs -Wait -PassThru; exit $p.ExitCode`,
		"NM_EXE="+exe, "NM_ARGS="+strings.Join(args, " "))
	return err
}

// Close asks the given processes to exit the way a user closing the window would.
func Close(pids []int) { taskkill(pids) }

// Kill ends the given processes immediately.
func Kill(pids []int) { taskkill(pids, "/F") }

func taskkill(pids []int, flags ...string) {
	for _, pid := range pids {
		cmd := exec.Command("taskkill.exe", append(flags, "/PID", strconv.Itoa(pid))...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
		_ = cmd.Run()
	}
}

// Notify shows a message box and waits until it is closed. It does not force
// itself above other windows: notices from the background come at random
// moments and should not cover what the user is doing.
func Notify(title, text string) {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	windows.MessageBox(0, m, t, windows.MB_OK|windows.MB_ICONINFORMATION|windows.MB_SETFOREGROUND)
}

// RemoveLater deletes path shortly after this process exits, so a running
// executable can remove the directory it lives in.
func RemoveLater(path string) error {
	cmd := powershellCmd(`Start-Sleep -Seconds 3; Remove-Item -LiteralPath $env:NM_PATH -Recurse -Force`, "NM_PATH="+path)
	return cmd.Start()
}

var (
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procAllocConsole     = kernel32.NewProc("AllocConsole")
	procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")
	procSetConsoleTitle  = kernel32.NewProc("SetConsoleTitleW")
)

// OpenConsole gives a windowless process a console window of its own and
// reports whether a console is available and whether it was created here,
// in which case it closes with the process. Output is switched to UTF-8 with
// ANSI colours.
func OpenConsole(title string) (available, created bool) {
	if hwnd, _, _ := procGetConsoleWindow.Call(); hwnd == 0 {
		if ok, _, _ := procAllocConsole.Call(); ok == 0 {
			return false, false
		}
		created = true
		if out, err := os.OpenFile("CONOUT$", os.O_RDWR, 0); err == nil {
			os.Stdout, os.Stderr = out, out
		}
		if in, err := os.OpenFile("CONIN$", os.O_RDWR, 0); err == nil {
			os.Stdin = in
		}
	}
	if t, err := windows.UTF16PtrFromString(title); err == nil {
		_, _, _ = procSetConsoleTitle.Call(uintptr(unsafe.Pointer(t)))
	}
	_ = windows.SetConsoleOutputCP(65001)
	_ = windows.SetConsoleCP(65001)
	out := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if windows.GetConsoleMode(out, &mode) == nil {
		_ = windows.SetConsoleMode(out, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	}
	return true, created
}

// OSVersion returns the Windows version and build, as in 10.0.22631.
func OSVersion() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}

func DocumentsDir() (string, error) {
	return windows.KnownFolderPath(windows.FOLDERID_Documents, 0)
}

func StartMenuDir() (string, error) {
	return windows.KnownFolderPath(windows.FOLDERID_Programs, 0)
}

func CreateShortcut(s Shortcut) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return err
	}
	// WScript.Shell is ANSI-only and fails on Cyrillic paths under a non-1251
	// code page, so the link is written through IShellLinkW instead.
	script := shellLinkType + `
[NoMintsifra.ShellLink]::Save($env:NM_LNK, $env:NM_TARGET, $env:NM_ARGS, $env:NM_ICON,` +
		` $env:NM_DESC, [IO.Path]::GetDirectoryName($env:NM_TARGET))`
	_, err := powershell(script,
		"NM_LNK="+s.Path, "NM_TARGET="+s.Target, "NM_ARGS="+s.Args, "NM_ICON="+s.Icon, "NM_DESC="+s.Description)
	return err
}
