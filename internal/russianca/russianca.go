// Package russianca checks server chains against the Russian Trusted Root CA
// in memory only. The root is never added to a system or browser store.
package russianca

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
)

//go:embed certs/root.pem
var rootPEM []byte

//go:embed certs/sub-ca.pem
var subCAPEM []byte

// Verifier checks that a chain is issued for a host under a fixed set of roots.
type Verifier struct {
	Roots         *x509.CertPool
	Intermediates []*x509.Certificate
}

// Default trusts the embedded Russian Trusted Root CA and knows its current
// Sub CA, for servers that leave the intermediate out.
var Default = &Verifier{Roots: pool(mustParse(rootPEM)), Intermediates: []*x509.Certificate{mustParse(subCAPEM)}}

// Root returns the embedded Ministry root certificate.
func Root() *x509.Certificate { return mustParse(rootPEM) }

// Verify reports whether chain[0] is valid for host and chains to the roots,
// using the rest of chain and the known intermediates as helpers.
func (v *Verifier) Verify(chain []*x509.Certificate, host string) error {
	_, err := v.Path(chain, host)
	return err
}

// Path verifies like Verify and returns the path it found, from chain[0]
// up to and including the root.
func (v *Verifier) Path(chain []*x509.Certificate, host string) ([]*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, errors.New("russianca: empty chain")
	}
	paths, err := chain[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         v.Roots,
		Intermediates: pool(append(chain[1:len(chain):len(chain)], v.Intermediates...)...),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return nil, err
	}
	return paths[0], nil
}

// WithIntermediates returns a verifier that also knows certs. Only CA
// certificates that themselves chain to v's roots are taken, so a list
// carrying them can add a newer Sub CA but never a CA of its own.
func (v *Verifier) WithIntermediates(certs []*x509.Certificate) *Verifier {
	known := slices.Clone(v.Intermediates)
	for _, c := range certs {
		if !c.IsCA || slices.ContainsFunc(known, c.Equal) {
			continue
		}
		_, err := c.Verify(x509.VerifyOptions{
			Roots:         v.Roots,
			Intermediates: pool(known...),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err == nil {
			known = append(known, c)
		}
	}
	return &Verifier{Roots: v.Roots, Intermediates: known}
}

// IsMinistryCA reports whether c is one of the Ministry's own certificate
// authorities, the root or a sub CA, in any of its generations.
func IsMinistryCA(c *x509.Certificate) bool {
	if !c.IsCA || !strings.HasPrefix(c.Subject.CommonName, "Russian Trusted ") {
		return false
	}
	for _, o := range c.Subject.Organization {
		if strings.Contains(o, "Ministry of Digital Development") {
			return true
		}
	}
	return false
}

func pool(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

func mustParse(data []byte) *x509.Certificate {
	block, _ := pem.Decode(data)
	if block == nil {
		panic("russianca: embedded certificate is not PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("russianca: " + err.Error())
	}
	return c
}
