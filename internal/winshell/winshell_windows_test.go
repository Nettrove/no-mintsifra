//go:build windows

package winshell

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseProcesses(t *testing.T) {
	cases := map[string]int{
		``:                                0,
		`{"PID":7,"CommandLine":"a.exe"}`: 1,
		`[{"PID":1,"CommandLine":"a"},{"PID":2,"CommandLine":""}]`: 2,
	}
	for in, want := range cases {
		got, err := parseProcesses([]byte(in))
		if err != nil || len(got) != want {
			t.Errorf("parseProcesses(%q) = %v, %v", in, got, err)
		}
	}
}

func TestProcessesFindsOwnImage(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	procs, err := Processes(exe)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range procs {
		if p.PID == os.Getpid() {
			return
		}
	}
	t.Fatalf("test process %d not listed among %v", os.Getpid(), procs)
}

func TestCreateShortcutRoundTrip(t *testing.T) {
	lnk := filepath.Join(t.TempDir(), "Тест — без Минцифры.lnk")
	want := Shortcut{Path: lnk, Target: `C:\Windows\System32\notepad.exe`, Args: `run brave`, Icon: `C:\Windows\System32\notepad.exe`, Description: "test"}
	if err := CreateShortcut(want); err != nil {
		t.Fatal(err)
	}

	// WScript.Shell cannot open non-ANSI paths, so read back through an ASCII copy.
	raw, err := os.ReadFile(lnk)
	if err != nil {
		t.Fatal(err)
	}
	ascii := filepath.Join(t.TempDir(), "copy.lnk")
	if err := os.WriteFile(ascii, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := powershell(`$l = (New-Object -ComObject WScript.Shell).CreateShortcut($env:NM_LNK); $l.TargetPath + '|' + $l.Arguments + '|' + $l.Description`, "NM_LNK="+ascii)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(string(out))
	if got != want.Target+"|run brave|test" {
		t.Fatalf("shortcut contents = %q", got)
	}
}
