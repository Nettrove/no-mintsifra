package main

import (
	"slices"
	"testing"
	"time"

	"github.com/Nettrove/no-mintsifra/internal/localca"
)

func TestCoverageDiff(t *testing.T) {
	added, removed := coverageDiff([]string{"gov.ru", "sberbank.ru", "vtb.ru"}, []string{"rosstat.gov.ru", "sberbank.ru", "tbank.ru", "vtb.ru"})
	if !slices.Equal(added, []string{"rosstat.gov.ru", "tbank.ru"}) || !slices.Equal(removed, []string{"gov.ru"}) {
		t.Fatalf("added %v, removed %v", added, removed)
	}
}

func TestMask(t *testing.T) {
	got := mask("\x1b[32m✓\x1b[0m key in "+`C:\Users\Ivan\AppData and c:\users\ivan\x`, `C:\Users\Ivan`)
	if got != `✓ key in %USERPROFILE%\AppData and %USERPROFILE%\x` {
		t.Fatalf("got %q", got)
	}
}

func TestCoverageNoticeOnce(t *testing.T) {
	have := []string{"sberbank.ru"}
	if msg, _ := coverageNotice(have, have, ""); msg != "" {
		t.Fatalf("notice for an unchanged list: %q", msg)
	}
	msg, key := coverageNotice(have, []string{"sberbank.ru", "vtb.ru"}, "")
	if msg == "" {
		t.Fatal("no notice for a new domain")
	}
	if again, _ := coverageNotice(have, []string{"sberbank.ru", "vtb.ru"}, key); again != "" {
		t.Fatal("same change announced twice")
	}
}

func TestExpiryNotice(t *testing.T) {
	now := time.Now()
	ca, err := localca.New([]string{"sberbank.ru"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if msg, _ := expiryNotice(ca.Cert, now, ""); msg != "" {
		t.Fatalf("warned about a fresh CA: %q", msg)
	}
	late := ca.Cert.NotAfter.Add(-30 * 24 * time.Hour)
	msg, key := expiryNotice(ca.Cert, late, "")
	if msg == "" {
		t.Fatal("no warning a month before expiry")
	}
	if again, _ := expiryNotice(ca.Cert, late, key); again != "" {
		t.Fatal("warned twice about the same CA")
	}
}

func TestNewer(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"v1.1.0", "v1.0.0", true},
		{"v1.0.10", "v1.0.9", true},
		{"v2.0.0", "v1.9.9", true},
		{"v1.0.0", "v1.0.0", false},
		{"v1.0.0", "v1.1.0", false},
		{"", "v1.0.0", false},
		{"v1.1.0", "dev", false},
		{"v1.1.0", "dev-41fa51d", false},
		{"v1.0.0", "v1.0.0-beta", true},
		{"v1.0.0-beta", "v1.0.0", false},
		{"v1.0.0-beta.2", "v1.0.0-beta", true},
		{"v1.0.0-beta.10", "v1.0.0-beta.9", true},
		{"v1.0.0-rc.1", "v1.0.0-beta.3", true},
		{"v1.0.0-beta", "v1.0.0-beta", false},
		{"v1.0.1-beta", "v1.0.0", true},
		{"v1.0.0-", "v0.9.0", false},
	} {
		if got := newer(tc.a, tc.b); got != tc.want {
			t.Errorf("newer(%q, %q) = %v", tc.a, tc.b, got)
		}
	}
}
