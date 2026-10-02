package sysproxy

import "strings"

// Manual is the user's own proxy, which WinINet keeps even while a PAC is set.
type Manual struct {
	Enabled  bool
	Server   string   // "host:port" or "http=h:p;https=h:p;socks=h:p"
	Override []string // ProxyOverride split on ';'
}

// Directive turns the manual proxy into a PAC result for the given scheme.
// It never appends DIRECT: a manual proxy in Windows fails closed, and
// silently bypassing a VPN would be worse than an error page.
func (m Manual) Directive(scheme string) string {
	if !m.Enabled || m.Server == "" {
		return "DIRECT"
	}
	if !strings.Contains(m.Server, "=") {
		return directive(m.Server, false)
	}
	by := map[string]string{}
	for _, part := range strings.Split(m.Server, ";") {
		if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok && v != "" {
			by[strings.ToLower(k)] = v
		}
	}
	switch {
	case by[scheme] != "":
		return directive(by[scheme], false)
	case by["socks"] != "":
		return directive(by["socks"], true)
	}
	return "DIRECT"
}

// directive formats one proxy address as a PAC result. Some clients write
// the address as a URL ("http://127.0.0.1:7890", "socks5://..."), which
// WinINet accepts but a PAC "PROXY" directive does not, so the scheme is
// dropped and a socks scheme picks the SOCKS directive.
func directive(addr string, socks bool) string {
	addr = strings.TrimSpace(addr)
	if scheme, rest, ok := strings.Cut(addr, "://"); ok {
		addr = rest
		socks = socks || strings.HasPrefix(strings.ToLower(scheme), "socks")
	}
	addr = strings.TrimSuffix(addr, "/")
	if socks {
		return "SOCKS5 " + addr + "; SOCKS " + addr
	}
	return "PROXY " + addr
}

// splitOverride turns ProxyOverride into its patterns, lowercased.
func splitOverride(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ";") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}
