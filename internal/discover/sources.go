package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxBody = 16 << 20

// DefaultSources returns the free passive-DNS and certificate-log lookups.
func DefaultSources(client *http.Client) []Source {
	return []Source{
		endpoint{"certspotter", "https://api.certspotter.com/v1/issuances?include_subdomains=true&expand=dns_names&domain=%s", client, parseCertspotter},
		endpoint{"crt.sh", "https://crt.sh/?output=json&q=%%25.%s", client, parseCrtsh},
		endpoint{"hackertarget", "https://api.hackertarget.com/hostsearch/?q=%s", client, parseHackertarget},
		endpoint{"anubis", "https://jldc.me/anubis/subdomains/%s", client, parseJSONStrings},
	}
}

type endpoint struct {
	name   string
	format string
	client *http.Client
	parse  func([]byte) []string
}

func (e endpoint) Name() string { return e.name }

func (e endpoint) Subdomains(ctx context.Context, domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(e.format, url.QueryEscape(domain)), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "no-mintsifra-pinbot")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: http %d", e.name, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	return e.parse(body), nil
}

func parseCertspotter(body []byte) []string {
	var issuances []struct {
		DNSNames []string `json:"dns_names"`
	}
	if json.Unmarshal(body, &issuances) != nil {
		return nil
	}
	var out []string
	for _, i := range issuances {
		out = append(out, i.DNSNames...)
	}
	return out
}

func parseCrtsh(body []byte) []string {
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if json.Unmarshal(body, &rows) != nil {
		return nil
	}
	var out []string
	for _, r := range rows {
		out = append(out, strings.Split(r.NameValue, "\n")...)
	}
	return out
}

func parseHackertarget(body []byte) []string {
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		if host, _, ok := strings.Cut(line, ","); ok {
			out = append(out, host)
		}
	}
	return out
}

func parseJSONStrings(body []byte) []string {
	var out []string
	if json.Unmarshal(body, &out) != nil {
		return nil
	}
	return out
}
