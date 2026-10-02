// Package localca is a certificate authority that exists only on this
// computer. Its name constraints limit it to the covered domains, so even a
// stolen key cannot vouch for any other site.
package localca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// CommonName names the CA in the certificate store.
const CommonName = "no-mintsifra local CA"

const (
	caLifetime   = 3 * 365 * 24 * time.Hour
	leafLifetime = 30 * 24 * time.Hour
	certFile     = "ca.crt"
	keyFile      = "ca.key"
)

type CA struct {
	Cert *x509.Certificate
	key  *ecdsa.PrivateKey

	mu      sync.Mutex
	leafKey *ecdsa.PrivateKey
	leaves  map[string]*tls.Certificate
}

// New creates a CA that may only issue for domains and their subdomains.
func New(domains []string, now time.Time) (*CA, error) {
	if len(domains) == 0 {
		return nil, errors.New("localca: no domains to cover")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject: pkix.Name{
			CommonName:   CommonName,
			Organization: []string{"no-mintsifra, only for " + host},
		},
		NotBefore:                   now.Add(-time.Hour),
		NotAfter:                    now.Add(caLifetime),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLenZero:              true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         slices.Sorted(slices.Values(domains)),
		ExcludedIPRanges: []*net.IPNet{
			{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, key: key}, nil
}

// Covers reports whether host falls under the CA's name constraints.
func (ca *CA) Covers(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range ca.Cert.PermittedDNSDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// Leaf returns a server certificate for host, reusing a cached one until it
// is a day away from expiry.
func (ca *CA) Leaf(host string, now time.Time) (*tls.Certificate, error) {
	host = strings.ToLower(host)
	if !ca.Covers(host) {
		return nil, fmt.Errorf("localca: %s is outside the covered domains", host)
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c := ca.leaves[host]; c != nil && now.Add(24*time.Hour).Before(c.Leaf.NotAfter) {
		return c, nil
	}
	if ca.leafKey == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		ca.leafKey, ca.leaves = k, map[string]*tls.Certificate{}
	}
	notAfter := now.Add(leafLifetime)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &ca.leafKey.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: ca.leafKey, Leaf: leaf}
	ca.leaves[host] = c
	return c, nil
}

// Save writes the certificate and the key, the key sealed to this Windows user.
func (ca *CA) Save(dir string) error {
	keyDER, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		return err
	}
	sealed, err := protect(keyDER)
	if err != nil {
		return fmt.Errorf("localca: seal key: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, keyFile), sealed, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, certFile), ca.Cert.Raw, 0o644)
}

func Load(dir string) (*CA, error) {
	raw, err := os.ReadFile(filepath.Join(dir, certFile))
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}
	sealed, err := os.ReadFile(filepath.Join(dir, keyFile))
	if err != nil {
		return nil, err
	}
	keyDER, err := unprotect(sealed)
	if err != nil {
		return nil, fmt.Errorf("localca: unseal key: %w", err)
	}
	key, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("localca: key does not match the certificate")
	}
	return &CA{Cert: cert, key: key}, nil
}

// Remove deletes the saved CA.
func Remove(dir string) error {
	for _, f := range []string{keyFile, certFile} {
		if err := os.Remove(filepath.Join(dir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n
}
