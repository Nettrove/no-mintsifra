package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Nettrove/no-mintsifra/internal/pins"
	"github.com/Nettrove/no-mintsifra/internal/probe"
)

const (
	retention      = 21 * 24 * time.Hour
	maxCertsPerPin = 6
	concurrency    = 24
)

type entry struct {
	Name    string   `yaml:"name"`
	Domains []string `yaml:"domains"`
	Hosts   []string `yaml:"hosts"`
}

type observer func(ctx context.Context, addr string) ([]probe.Observation, error)

// expander lists the hostnames that exist under a domain.
type expander func(ctx context.Context, domain string) []string

func loadCatalog(path string) ([]entry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []entry
	if err := yaml.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("catalog %s: %w", path, err)
	}
	return entries, nil
}

// build scans the catalog and folds the result into prev, keeping pins that
// disappeared only for the retention window. Domains are enumerated for
// subdomains only once their apex or www is seen on the Russian Trusted CA,
// and hosts found earlier are probed again so the host list only grows while
// the sites keep answering.
func build(ctx context.Context, entries []entry, prev *pins.Set, now time.Time, observe observer, expand expander) (*pins.Set, []string) {
	return assemble(entries, prev, now, scanCatalog(ctx, entries, prev, observe, expand))
}

// scanCatalog probes the hosts of every entry, and the subdomains of each
// domain whose apex or www is seen on the Russian Trusted CA.
func scanCatalog(ctx context.Context, entries []entry, prev *pins.Set, observe observer, expand expander) *scanner {
	scanner := &scanner{observe: observe}
	for _, e := range entries {
		scanner.scan(ctx, seedHosts(e, previousSite(prev, e.Name).Hosts))
		for _, domain := range e.Domains {
			if scanner.russianUnder(domain) {
				scanner.scan(ctx, expand(ctx, domain))
			}
		}
	}
	return scanner
}

// assemble turns what the scanner saw into a set, entry by entry.
func assemble(entries []entry, prev *pins.Set, now time.Time, scanner *scanner) (*pins.Set, []string) {
	var warnings []string
	out := &pins.Set{Schema: pins.SchemaV2, Generated: now.UTC().Truncate(time.Second)}
	for _, e := range entries {
		previous := previousSite(prev, e.Name)
		seeds := seedHosts(e, previous.Hosts)
		hosts, observed := scanner.collect(e, seeds)
		merged := mergePins(observed, previous.Pins, now)
		if len(merged) == 0 {
			if len(previous.Pins) > 0 {
				warnings = append(warnings, fmt.Sprintf("%s: no pins this run, previous ones expired or were dropped", e.Name))
			}
			continue
		}
		out.Sites = append(out.Sites, pins.Site{Name: e.Name, Hosts: hosts, Pins: merged})
	}
	sort.Slice(out.Sites, func(i, j int) bool { return out.Sites[i].Name < out.Sites[j].Name })
	var previous []*x509.Certificate
	if prev != nil {
		previous = prev.IntermediateCerts()
	}
	out.Intermediates = mergeIntermediates(scanner.intermediates(), previous, now)
	return out, warnings
}

// mergeIntermediates keeps every Sub CA seen now or before that has not
// expired: leaves issued under an older generation stay valid after a new
// one appears.
func mergeIntermediates(seen, previous []*x509.Certificate, now time.Time) []string {
	byFingerprint := map[string]*x509.Certificate{}
	for _, c := range append(seen, previous...) {
		if now.Before(c.NotAfter) {
			byFingerprint[pins.Fingerprint(c)] = c
		}
	}
	keys := make([]string, 0, len(byFingerprint))
	for k := range byFingerprint {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, base64.StdEncoding.EncodeToString(byFingerprint[k].Raw))
	}
	return out
}

func seedHosts(e entry, known []string) []string {
	seen := map[string]struct{}{}
	add := func(h string) { seen[strings.ToLower(h)] = struct{}{} }
	for _, h := range e.Hosts {
		add(h)
	}
	for _, h := range known {
		add(h)
	}
	for _, d := range e.Domains {
		add(d)
		add("www." + d)
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// scanner probes each host once and remembers what it saw.
type scanner struct {
	observe observer

	mu   sync.Mutex
	seen map[string][]probe.Observation
}

func (s *scanner) scan(ctx context.Context, hosts []string) {
	s.mu.Lock()
	if s.seen == nil {
		s.seen = map[string][]probe.Observation{}
	}
	var todo []string
	for _, h := range hosts {
		if _, done := s.seen[h]; !done {
			s.seen[h] = nil
			todo = append(todo, h)
		}
	}
	s.mu.Unlock()

	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for _, host := range todo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			obs, err := s.observe(ctx, host)
			if err != nil {
				return
			}
			s.mu.Lock()
			s.seen[host] = obs
			s.mu.Unlock()
		}()
	}
	wg.Wait()
}

// intermediates returns the Sub CAs of every Russian chain seen so far.
func (s *scanner) intermediates() []*x509.Certificate {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*x509.Certificate
	for _, obs := range s.seen {
		for _, o := range obs {
			if pinnable(o) {
				out = append(out, o.Intermediates...)
			}
		}
	}
	return out
}

func (s *scanner) russianUnder(domain string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for host, obs := range s.seen {
		if host != domain && !strings.HasSuffix(host, "."+domain) {
			continue
		}
		for _, o := range obs {
			if pinnable(o) {
				return true
			}
		}
	}
	return false
}

// collect returns the pinnable observations that belong to entry e, together
// with the hosts they came from.
func (s *scanner) collect(e entry, seeds []string) ([]string, []probe.Observation) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var hosts []string
	var observed []probe.Observation
	for host, obs := range s.seen {
		if !belongs(host, e, seeds) {
			continue
		}
		kept := false
		for _, o := range obs {
			if pinnable(o) {
				observed = append(observed, o)
				kept = true
			}
		}
		if kept {
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)
	return hosts, observed
}

func belongs(host string, e entry, seeds []string) bool {
	for _, s := range seeds {
		if s == host {
			return true
		}
	}
	for _, d := range e.Domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// pinnable limits pins to certificates from the Russian Trusted CA that the
// system does not already accept, so unrelated self-signed or expired
// certificates never widen the allowlist.
func pinnable(o probe.Observation) bool {
	return o.RussianCA && !o.Trusted
}

func previousSite(prev *pins.Set, name string) pins.Site {
	if prev == nil {
		return pins.Site{}
	}
	for _, s := range prev.Sites {
		if s.Name == name {
			return s
		}
	}
	return pins.Site{}
}

func mergePins(observed []probe.Observation, previous []pins.Pin, now time.Time) []pins.Pin {
	day := now.UTC().Truncate(24 * time.Hour)
	bySPKI := map[string]*pins.Pin{}

	for _, o := range observed {
		p := bySPKI[o.SPKI]
		if p == nil {
			p = &pins.Pin{SPKI: o.SPKI, LastSeen: day}
			bySPKI[o.SPKI] = p
		}
		p.Certs = appendUnique(p.Certs, o.Fingerprint)
		if o.NotAfter.After(p.NotAfter) {
			p.NotAfter = o.NotAfter.UTC()
		}
	}

	for _, old := range previous {
		if p, ok := bySPKI[old.SPKI]; ok {
			for _, c := range old.Certs {
				p.Certs = appendUnique(p.Certs, c)
			}
			continue
		}
		if old.Active(now) && day.Sub(old.LastSeen) <= retention {
			kept := old
			bySPKI[old.SPKI] = &kept
		}
	}

	out := make([]pins.Pin, 0, len(bySPKI))
	for _, p := range bySPKI {
		if len(p.Certs) > maxCertsPerPin {
			p.Certs = p.Certs[:maxCertsPerPin]
		}
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SPKI < out[j].SPKI })
	return out
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
