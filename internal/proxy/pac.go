package proxy

import (
	"encoding/json"
	"fmt"
	"slices"
)

// Others says where the browser should send hosts outside the list: the
// PAC results for http and https, and the patterns that bypass them.
type Others struct {
	HTTP, HTTPS string
	// Bypass holds shExpMatch patterns; "<local>" stands for plain host names.
	Bypass []string
}

// Direct sends everything outside the list straight to the server.
var Direct = Others{HTTP: "DIRECT", HTTPS: "DIRECT"}

// PAC builds a proxy auto-config script that sends the covered domains through
// addr and everything else where others says. The covered domains are checked
// first: a VPN client's typical bypass for *.ru must not route a bank past
// the proxy. Plain HTTP to them goes through too, so the proxy can move it to
// HTTPS. If the proxy is down the browser falls back to a direct connection,
// since these sites do not need a VPN.
func PAC(addr string, domains []string, others Others) []byte {
	local := slices.Contains(others.Bypass, "<local>")
	// Empty lists must stay arrays: null would throw inside the browser.
	bypass := []string{}
	for _, p := range others.Bypass {
		if p != "<local>" {
			bypass = append(bypass, p)
		}
	}
	list, _ := json.Marshal(append([]string{}, domains...))
	patterns, _ := json.Marshal(bypass)
	httpDirective, _ := json.Marshal(others.HTTP)
	httpsDirective, _ := json.Marshal(others.HTTPS)
	return fmt.Appendf(nil, `var domains = %s;
var bypass = %s;
var bypassLocal = %t;
function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  var https = url.substring(0, 6) == "https:";
  if (https || url.substring(0, 5) == "http:") {
    for (var i = 0; i < domains.length; i++) {
      var d = domains[i];
      if (host == d || dnsDomainIs(host, "." + d)) return "PROXY %s; DIRECT";
    }
  }
  if (host == "localhost" || shExpMatch(host, "127.*") || host == "::1" || host == "[::1]") return "DIRECT";
  if (bypassLocal && isPlainHostName(host)) return "DIRECT";
  for (var j = 0; j < bypass.length; j++) {
    if (shExpMatch(host, bypass[j])) return "DIRECT";
  }
  return https ? %s : %s;
}
`, list, patterns, local, addr, httpsDirective, httpDirective)
}
