// Package discover finds the hostnames that exist under a domain, combining
// passive sources with a list of common names and a DNS check.
package discover

import (
	"context"
	_ "embed"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
)

//go:embed words.txt
var wordlist string

const (
	maxCandidates  = 600
	resolveWorkers = 32
)

var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

type Source interface {
	Name() string
	Subdomains(ctx context.Context, domain string) ([]string, error)
}

type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Hosts returns every resolvable name under domain (including domain itself).
// A failing source is skipped: the others and the wordlist still contribute.
func Hosts(ctx context.Context, domain string, sources []Source, res Resolver) []string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	candidates := map[string]struct{}{domain: {}, "www." + domain: {}}

	for _, word := range strings.Fields(wordlist) {
		candidates[word+"."+domain] = struct{}{}
	}
	for _, src := range sources {
		names, err := src.Subdomains(ctx, domain)
		if err != nil {
			continue
		}
		for _, n := range names {
			if n = clean(n, domain); n != "" {
				candidates[n] = struct{}{}
			}
		}
	}

	return resolvable(ctx, limit(candidates), res)
}

// clean normalises a source-provided name, dropping wildcards and strangers.
func clean(name, domain string) string {
	name = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(name)), "*.")
	if name != domain && !strings.HasSuffix(name, "."+domain) {
		return ""
	}
	if !hostRe.MatchString(name) {
		return ""
	}
	return name
}

// limit keeps the shortest names, which favours real service hosts over
// generated ones and always retains the bare domain.
func limit(set map[string]struct{}) []string {
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) < len(names[j])
		}
		return names[i] < names[j]
	})
	if len(names) > maxCandidates {
		names = names[:maxCandidates]
	}
	return names
}

func resolvable(ctx context.Context, names []string, res Resolver) []string {
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, resolveWorkers)
		out []string
	)
	for _, name := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if addrs, err := res.LookupHost(ctx, name); err == nil && len(addrs) > 0 {
				mu.Lock()
				out = append(out, name)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	sort.Strings(out)
	return out
}

// System resolves through the operating system.
type System struct{}

func (System) LookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}
