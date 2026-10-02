package pins

import (
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// sharedDomains host many unrelated services or users under one name, so a
// Ministry certificate on one of their hosts says nothing about the rest.
// They are covered only host by host, and never as a whole.
var sharedDomains = []string{
	"gov.ru",
	"mail.ru", "list.ru", "bk.ru", "inbox.ru", "internet.ru",
	"yandex.ru", "yandex.net", "yandex.com", "ya.ru", "dzen.ru",
	"vk.com", "vk.ru", "vkontakte.ru", "ok.ru", "max.ru",
	"rambler.ru", "lenta.ru",
	"narod.ru", "ucoz.ru", "tilda.ws", "livejournal.com",
	"reg.ru", "nic.ru", "beget.com", "timeweb.ru", "selectel.ru", "yandexcloud.net",
}

// neverCovered are services whose traffic must never pass through the local
// CA, whatever a signed list says. This guards the users if the list signing
// key is ever stolen.
var neverCovered = []string{
	"google.com", "google.ru", "googleapis.com", "gstatic.com", "gmail.com", "youtube.com",
	"apple.com", "icloud.com",
	"microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com",
	"windows.com", "windowsupdate.com",
	"telegram.org", "telegram.me", "t.me",
	"whatsapp.com", "whatsapp.net",
	"signal.org",
	"proton.me", "protonmail.com",
	"github.com", "githubusercontent.com",
	"mozilla.org", "firefox.com",
	"cloudflare.com", "letsencrypt.org",
	"wikipedia.org", "facebook.com", "instagram.com", "x.com", "twitter.com", "discord.com",
	"bitwarden.com", "1password.com",
}

// Coverage returns the names the local CA may issue for, each covering
// itself and its subdomains. A registrable domain is covered as a whole
// only when its apex or www host is itself served from a Ministry
// certificate; otherwise only the listed hosts are. Shared domains are
// always covered host by host, and the never-covered services not at all.
func (s *Set) Coverage() []string {
	hosts := s.Hosts()
	whole := map[string]bool{}
	for _, h := range hosts {
		if d, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil && (h == d || h == "www."+d) {
			whole[d] = true
		}
	}

	var out []string
	for _, h := range hosts {
		h = strings.TrimPrefix(h, "*.")
		d, err := publicsuffix.EffectiveTLDPlusOne(h)
		switch {
		case err != nil, under(h, neverCovered):
			continue
		case slices.Contains(sharedDomains, d):
			if h != d {
				out = append(out, h)
			}
		case whole[d]:
			out = append(out, d)
		default:
			out = append(out, h)
		}
	}
	return collapse(out)
}

// HeldBack returns the listed hosts that Coverage leaves out on purpose: the
// never-covered services and the apex of a shared domain, which a name
// constraint cannot cover without taking in all of its subdomains too.
func (s *Set) HeldBack() []string {
	coverage := s.Coverage()
	var out []string
	for _, h := range s.Hosts() {
		if !Covers(coverage, strings.TrimPrefix(h, "*.")) {
			out = append(out, h)
		}
	}
	return out
}

// Covers reports whether host falls under one of the coverage names.
func Covers(coverage []string, host string) bool {
	return under(strings.ToLower(strings.TrimSuffix(host, ".")), coverage)
}

// under reports whether host is one of domains or a subdomain of one.
func under(host string, domains []string) bool {
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// collapse sorts names and drops those already covered by a shorter one.
func collapse(names []string) []string {
	slices.SortFunc(names, func(a, b string) int {
		if len(a) != len(b) {
			return len(a) - len(b)
		}
		return strings.Compare(a, b)
	})
	var out []string
	for _, n := range names {
		if !under(n, out) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}
