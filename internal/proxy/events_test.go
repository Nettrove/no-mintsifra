package proxy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogKeepsTheLatestEvents(t *testing.T) {
	l := NewLog("", 3, 0)
	for i := range 5 {
		l.Add(Event{Host: fmt.Sprint(i), Stage: StageDial, Err: "line\nbreak"})
	}
	var got []string
	for _, e := range l.Recent() {
		got = append(got, e.Host)
		if strings.ContainsAny(e.Err, "\n\t") {
			t.Fatalf("control characters kept: %q", e.Err)
		}
	}
	if strings.Join(got, ",") != "2,3,4" {
		t.Fatalf("recent = %v", got)
	}
}

func TestLogFlushRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.log")
	l := NewLog(path, 10, 100)
	for round := range 3 {
		for range 2 {
			l.Add(Event{Time: time.Unix(0, 0).UTC(), Host: "online.example.ru", Stage: StageVerify, Err: fmt.Sprint("round ", round)})
		}
		if err := l.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	cur, _ := os.ReadFile(path)
	old, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal("no rotated file:", err)
	}
	// One older generation is kept, so disk use stays at about twice MaxSize.
	if !strings.Contains(string(cur), "round 2") || !strings.Contains(string(old), "round 1") || strings.Contains(string(cur)+string(old), "round 0") {
		t.Fatalf("current:\n%s\nrotated:\n%s", cur, old)
	}
}
