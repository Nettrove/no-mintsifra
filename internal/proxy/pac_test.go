package proxy

import (
	"regexp"
	"strings"
	"testing"

	"github.com/dop251/goja"
)

// runPAC evaluates script the way a browser does, with the Netscape helper
// functions it relies on, and returns a function that resolves a URL.
func runPAC(t *testing.T, script []byte) func(url string) string {
	t.Helper()
	vm := goja.New()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(vm.Set("dnsDomainIs", func(host, domain string) bool { return strings.HasSuffix(host, domain) }))
	must(vm.Set("isPlainHostName", func(host string) bool { return !strings.Contains(host, ".") }))
	must(vm.Set("shExpMatch", func(s, pattern string) bool {
		re := "^" + strings.NewReplacer(`\*`, ".*", `\?`, ".").Replace(regexp.QuoteMeta(pattern)) + "$"
		return regexp.MustCompile(re).MatchString(s)
	}))
	if _, err := vm.RunString(string(script)); err != nil {
		t.Fatalf("PAC does not run: %v\n%s", err, script)
	}
	find, ok := goja.AssertFunction(vm.Get("FindProxyForURL"))
	if !ok {
		t.Fatal("FindProxyForURL is not defined")
	}
	return func(url string) string {
		host := url[strings.Index(url, "://")+3:]
		host = strings.SplitN(host, "/", 2)[0]
		v, err := find(goja.Undefined(), vm.ToValue(url), vm.ToValue(host))
		if err != nil {
			t.Fatal(err)
		}
		return v.String()
	}
}

func TestPACRoutes(t *testing.T) {
	const ours = "PROXY 127.0.0.1:47123; DIRECT"
	vpn := Others{
		HTTP:   "PROXY 127.0.0.1:10809",
		HTTPS:  "SOCKS5 127.0.0.1:10808; SOCKS 127.0.0.1:10808",
		Bypass: []string{"*.ru", "10.*", "<local>"},
	}
	for _, tc := range []struct {
		name   string
		others Others
		url    string
		want   string
	}{
		{"covered host", Direct, "https://online.sberbank.ru/", ours},
		{"covered apex", Direct, "https://sberbank.ru/", ours},
		{"covered plain http", Direct, "http://sberbank.ru/", ours},
		{"covered beats the VPN bypass", vpn, "https://online.sberbank.ru/", ours},
		{"look-alike is not covered", Direct, "https://evilsberbank.ru/", "DIRECT"},
		{"other host without a manual proxy", Direct, "https://example.com/", "DIRECT"},
		{"other https host goes to the VPN", vpn, "https://example.com/", vpn.HTTPS},
		{"other http host goes to the VPN", vpn, "http://example.com/", vpn.HTTP},
		{"VPN bypass pattern", vpn, "https://yandex.ru/", "DIRECT"},
		{"VPN bypass for an address", vpn, "http://10.0.0.1/", "DIRECT"},
		{"<local> means plain names", vpn, "http://router/", "DIRECT"},
		{"loopback never leaves", vpn, "http://localhost:8080/", "DIRECT"},
		{"loopback address never leaves", vpn, "http://127.0.0.1/", "DIRECT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolve := runPAC(t, PAC("127.0.0.1:47123", []string{"sberbank.ru", "vtb.ru"}, tc.others))
			if got := resolve(tc.url); got != tc.want {
				t.Fatalf("%s: got %q, want %q", tc.url, got, tc.want)
			}
		})
	}
}

func TestPACNeverFallsBackPastTheVPN(t *testing.T) {
	vpn := Others{HTTP: "PROXY 10.8.0.1:3128", HTTPS: "PROXY 10.8.0.1:3128"}
	resolve := runPAC(t, PAC("127.0.0.1:47123", []string{"sberbank.ru"}, vpn))
	for _, url := range []string{"https://example.com/", "http://example.com/"} {
		if got := resolve(url); strings.Contains(got, "DIRECT") {
			t.Fatalf("%s may bypass the VPN: %q", url, got)
		}
	}
}
