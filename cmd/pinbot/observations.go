package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"time"

	"github.com/Nettrove/no-mintsifra/internal/probe"
)

const (
	// maxObservations bounds the file a probe may hand over.
	maxObservations = 64 << 20
	// maxObservationAge drops a probe's file that was not refreshed: replaying
	// an old one would keep a host in the list after it left the Ministry's
	// certificates, until the old certificate expired.
	maxObservationAge = 48 * time.Hour
	// clockSkew tolerates a probe whose clock runs slightly ahead.
	clockSkew = time.Hour
)

var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

func validHost(h string) bool { return hostRe.MatchString(h) }

// observations is what a probe publishes: the chains each host presented,
// as base64 DER, leaf first. It carries no verdicts; the reader forms its own.
type observations struct {
	Generated time.Time             `json:"generated"`
	Hosts     map[string][][]string `json:"hosts"`
}

// export writes every chain the scanner saw.
func (s *scanner) export(w io.Writer, now time.Time) error {
	s.mu.Lock()
	out := observations{Generated: now.UTC().Truncate(time.Second), Hosts: map[string][][]string{}}
	for host, obs := range s.seen {
		for _, o := range obs {
			var chain []string
			for _, c := range o.Chain {
				chain = append(chain, base64.StdEncoding.EncodeToString(c.Raw))
			}
			if len(chain) > 0 {
				out.Hosts[host] = append(out.Hosts[host], chain)
			}
		}
	}
	s.mu.Unlock()
	for _, chains := range out.Hosts {
		sort.Slice(chains, func(i, j int) bool { return chains[i][0] < chains[j][0] })
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	return enc.Encode(out)
}

// readObservations loads a probe's chains. Malformed chains are dropped, and
// a file generated more than maxObservationAge before now is refused.
func readObservations(path string, now time.Time) (map[string][][]*x509.Certificate, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxObservations+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxObservations {
		return nil, errors.New("observations: file too large")
	}
	var in observations
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	switch age := now.Sub(in.Generated); {
	case in.Generated.IsZero():
		return nil, errors.New("observations: no generation time")
	case age > maxObservationAge:
		return nil, fmt.Errorf("observations: generated %s ago, older than %s", age.Round(time.Minute), maxObservationAge)
	case age < -clockSkew:
		return nil, errors.New("observations: generated in the future")
	}
	out := map[string][][]*x509.Certificate{}
	for host, chains := range in.Hosts {
		for _, encoded := range chains {
			if chain, ok := decodeChain(encoded); ok {
				out[host] = append(out[host], chain)
			}
		}
	}
	return out, nil
}

func decodeChain(encoded []string) ([]*x509.Certificate, bool) {
	var chain []*x509.Certificate
	for _, e := range encoded {
		der, err := base64.StdEncoding.DecodeString(e)
		if err != nil {
			return nil, false
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, false
		}
		chain = append(chain, c)
	}
	return chain, len(chain) > 0
}

// add judges chains seen elsewhere as if they were seen here: the verdicts
// come from probe.FromChain, against the embedded root, the host name and
// the current time, never from the observer.
func (s *scanner) add(external map[string][][]*x509.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[string][]probe.Observation{}
	}
	for host, chains := range external {
		if !validHost(host) {
			continue
		}
	next:
		for _, chain := range chains {
			o := probe.FromChain(host, chain)
			for _, have := range s.seen[host] {
				if have.Fingerprint == o.Fingerprint {
					continue next
				}
			}
			s.seen[host] = append(s.seen[host], o)
		}
	}
}
