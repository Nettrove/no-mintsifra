package pins

import (
	"slices"
	"testing"
)

func setOf(hosts ...string) *Set {
	return &Set{Sites: []Site{{Name: "s", Hosts: hosts}}}
}

func TestCoverage(t *testing.T) {
	got := setOf(
		"online.sberbank.ru", "www.sberbank.ru", // apex on the Ministry CA: whole domain
		"online.vtb.ru", "*.cdn.vtb.ru", // apex not seen: hosts only
		"a.cdn.vtb.ru",                      // already under *.cdn.vtb.ru
		"id.vk.com", "vk.com", "www.vk.com", // shared: hosts only, never the apex
		"esia.gosuslugi.ru", "www.gosuslugi.ru", // one operator: whole domain
		"rosstat.gov.ru", "www.rosstat.gov.ru",
		"e.mail.ru",
	).Coverage()
	want := []string{"cdn.vtb.ru", "e.mail.ru", "gosuslugi.ru", "id.vk.com", "online.vtb.ru", "rosstat.gov.ru", "sberbank.ru", "www.vk.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestHeldBack(t *testing.T) {
	got := setOf("vk.com", "www.vk.com", "online.sberbank.ru", "mail.google.com").HeldBack()
	if want := []string{"mail.google.com", "vk.com"}; !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCoverageNeverTakesSharedDomainsWhole(t *testing.T) {
	for _, d := range sharedDomains {
		got := setOf(d, "www."+d, "pay."+d, "*."+d).Coverage()
		if slices.Contains(got, d) {
			t.Errorf("%s covered as a whole: %q", d, got)
		}
		if !slices.Contains(got, "pay."+d) {
			t.Errorf("%s: listed host dropped: %q", d, got)
		}
	}
}

func TestCoverageDropsNeverCoveredWhateverTheList(t *testing.T) {
	var hosts []string
	for _, d := range neverCovered {
		hosts = append(hosts, d, "www."+d, "login."+d, "*."+d)
	}
	hosts = append(hosts, "online.sberbank.ru", "www.sberbank.ru")
	got := setOf(hosts...).Coverage()
	for _, name := range got {
		if under(name, neverCovered) {
			t.Errorf("covered %s", name)
		}
	}
	if !slices.Equal(got, []string{"sberbank.ru"}) {
		t.Fatalf("got %q", got)
	}
}
