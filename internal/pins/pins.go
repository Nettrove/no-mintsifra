// Package pins describes the signed list of hosts served from the Russian
// Trusted CA, together with the leaf keys seen on each.
package pins

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"time"
)

const (
	// SchemaVersion is the format every released client reads.
	SchemaVersion = 1
	// SchemaV2 adds the intermediate certificates. Older clients reject it,
	// so it is published next to the version 1 file, never in its place.
	SchemaV2 = 2
)

type Pin struct {
	SPKI     string    `json:"spki"`
	Certs    []string  `json:"certs"`
	NotAfter time.Time `json:"notAfter"`
	LastSeen time.Time `json:"lastSeen"`
}

type Site struct {
	Name  string   `json:"name"`
	Hosts []string `json:"hosts"`
	Pins  []Pin    `json:"pins"`
}

type Set struct {
	Schema    int       `json:"schema"`
	Generated time.Time `json:"generated"`
	Sites     []Site    `json:"sites"`
	// Intermediates holds the base64 DER of every Sub CA seen under the
	// Russian root, so a new generation reaches clients without a release.
	Intermediates []string `json:"intermediates,omitempty"`
}

var (
	hostRe = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	certRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func SPKI(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func Parse(data []byte) (*Set, error) {
	var s Set
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("pins: decode: %w", err)
	}
	if s.Schema != SchemaVersion && s.Schema != SchemaV2 {
		return nil, fmt.Errorf("pins: unsupported schema %d", s.Schema)
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *Set) validate() error {
	if s.Schema == SchemaVersion && len(s.Intermediates) > 0 {
		return fmt.Errorf("pins: schema %d has no intermediates", s.Schema)
	}
	for _, raw := range s.Intermediates {
		der, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return fmt.Errorf("pins: invalid intermediate: %w", err)
		}
		if c, err := x509.ParseCertificate(der); err != nil || !c.IsCA {
			return fmt.Errorf("pins: intermediate is not a CA certificate")
		}
	}
	for _, site := range s.Sites {
		for _, h := range site.Hosts {
			if !hostRe.MatchString(h) {
				return fmt.Errorf("pins: %s: invalid host %q", site.Name, h)
			}
		}
		for _, p := range site.Pins {
			if raw, err := base64.StdEncoding.DecodeString(p.SPKI); err != nil || len(raw) != sha256.Size {
				return fmt.Errorf("pins: %s: invalid spki %q", site.Name, p.SPKI)
			}
			for _, c := range p.Certs {
				if !certRe.MatchString(c) {
					return fmt.Errorf("pins: %s: invalid cert fingerprint %q", site.Name, c)
				}
			}
		}
	}
	return nil
}

// IntermediateCerts returns the parsed intermediates.
func (s *Set) IntermediateCerts() []*x509.Certificate {
	var out []*x509.Certificate
	for _, raw := range s.Intermediates {
		if der, err := base64.StdEncoding.DecodeString(raw); err == nil {
			if c, err := x509.ParseCertificate(der); err == nil {
				out = append(out, c)
			}
		}
	}
	return out
}

// V1 returns the set in the format older clients read.
func (s *Set) V1() *Set {
	v1 := *s
	v1.Schema, v1.Intermediates = SchemaVersion, nil
	return &v1
}

func (s *Set) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p Pin) Active(now time.Time) bool {
	return p.NotAfter.After(now)
}

func (s *Set) SPKIs(now time.Time) []string {
	seen := map[string]struct{}{}
	for _, site := range s.Sites {
		for _, p := range site.Pins {
			if p.Active(now) {
				seen[p.SPKI] = struct{}{}
			}
		}
	}
	return sortedKeys(seen)
}

func (s *Set) Hosts() []string {
	seen := map[string]struct{}{}
	for _, site := range s.Sites {
		for _, h := range site.Hosts {
			seen[h] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
