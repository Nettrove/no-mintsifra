// Package probe reads the certificate chains a TLS server presents.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sort"
	"time"

	"github.com/Nettrove/no-mintsifra/internal/pins"
	"github.com/Nettrove/no-mintsifra/internal/russianca"
)

type Observation struct {
	Host        string
	SPKI        string
	Fingerprint string
	Issuer      string
	NotAfter    time.Time
	// Trusted reports whether the chain already verifies against the system roots.
	Trusted bool
	// RussianCA reports whether the chain is issued for Host under the
	// Russian Trusted Root CA.
	RussianCA bool
	// Intermediates are the Sub CAs between the leaf and the Russian root.
	Intermediates []*x509.Certificate
	// Chain is everything the server presented, leaf first.
	Chain []*x509.Certificate
}

var russian = russianca.Default

var variants = []func() *tls.Config{
	func() *tls.Config { return &tls.Config{} },
	func() *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		}}
	},
	func() *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		}}
	},
}

// Observe connects to addr (host or host:port) once per client profile and
// returns every distinct leaf certificate the server handed out.
func Observe(ctx context.Context, addr string) ([]Observation, error) {
	host, port := splitAddr(addr)
	byFingerprint := map[string]Observation{}
	var lastErr error

	for _, newConfig := range variants {
		chain, err := fetchChain(ctx, host, port, newConfig())
		if err != nil {
			lastErr = err
			continue
		}
		fp := pins.Fingerprint(chain[0])
		if _, dup := byFingerprint[fp]; dup {
			continue
		}
		byFingerprint[fp] = FromChain(host, chain)
	}
	if len(byFingerprint) == 0 {
		return nil, lastErr
	}

	out := make([]Observation, 0, len(byFingerprint))
	for _, o := range byFingerprint {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out, nil
}

// FromChain judges a chain presented for host. Every verdict is computed
// here, against the embedded root and the current time, so a chain read by
// someone else is judged the same as one read by Observe.
func FromChain(host string, chain []*x509.Certificate) Observation {
	leaf := chain[0]
	path, err := russian.Path(chain, host)
	o := Observation{
		Host:        host,
		SPKI:        pins.SPKI(leaf),
		Fingerprint: pins.Fingerprint(leaf),
		Issuer:      leaf.Issuer.CommonName,
		NotAfter:    leaf.NotAfter,
		Trusted:     verifies(chain, host),
		RussianCA:   err == nil,
		Chain:       chain,
	}
	if len(path) > 2 {
		o.Intermediates = path[1 : len(path)-1]
	}
	return o
}

func fetchChain(ctx context.Context, host, port string, cfg *tls.Config) ([]*x509.Certificate, error) {
	// Verification is skipped on purpose: only the presented certificates are
	// read, no request is sent and nothing from the session is trusted.
	cfg.InsecureSkipVerify = true
	cfg.ServerName = host

	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 8 * time.Second}, Config: cfg}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	chain := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, errors.New("probe: server presented no certificates")
	}
	return chain, nil
}

func verifies(chain []*x509.Certificate, host string) bool {
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: intermediates})
	return err == nil
}

func splitAddr(addr string) (host, port string) {
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return h, p
	}
	return addr, "443"
}
