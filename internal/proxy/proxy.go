// Package proxy terminates TLS for the covered hosts on the loopback address
// and relays the bytes to the real server once its certificate checks out.
// It never parses or records what passes through, and refuses every other host.
// Toward the bank it sends the browser's own ClientHello shape, so bot filters
// that match the TLS fingerprint against the User-Agent see the real browser.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/Nettrove/no-mintsifra/internal/localca"
	"github.com/Nettrove/no-mintsifra/internal/pins"
	"github.com/Nettrove/no-mintsifra/internal/russianca"
)

const (
	PACPath          = "/proxy.pac"
	handshakeTimeout = 20 * time.Second
	// Room for one maximum-size TLS record behind the CONNECT request.
	readBuffer = 5 + 16384 + 4096
)

type Server struct {
	CA *localca.CA
	// PAC builds the proxy auto-config script for each request, so it can
	// follow settings that change while the proxy runs.
	PAC func() []byte
	// Log receives every failed connection; nil keeps nothing.
	Log *Log
	// Pinned reports whether a leaf key is in the signed list. A Russian
	// chain whose leaf is not is still let through, but logged once per
	// host: the list may lag behind a reissue, or the site may be spoofed.
	Pinned func(spki string) bool
	warned sync.Map

	// Optional overrides, for tests.
	Dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	Verify func(chain []*x509.Certificate, host string) error
	Now    func() time.Time
}

func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	// One bad connection must not take the proxy, and every site, down with it.
	defer func() {
		if r := recover(); r != nil {
			s.record(c.RemoteAddr().String(), StageRecovered, fmt.Errorf("%v", r))
		}
	}()
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	br := bufio.NewReaderSize(c, readBuffer)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	switch {
	case req.Method == http.MethodConnect:
		s.connect(&bufferedConn{Conn: c, r: br}, br, req.Host)
	case req.Method == http.MethodGet && req.URL.Path == PACPath && req.URL.Host == "":
		pac := s.PAC()
		fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nCache-Control: no-store\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(pac))
		_, _ = c.Write(pac)
	case req.URL.Scheme == "http" && s.CA.Covers(req.URL.Hostname()) && (req.URL.Port() == "" || req.URL.Port() == "80"):
		upgrade(c, req)
	default:
		io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
	}
}

// upgrade sends a plain HTTP request for a covered host to its HTTPS address.
// Some of these sites do not answer on port 80 at all, and browsers that fail
// to upgrade a link in time fall back to it and hang.
func upgrade(c net.Conn, req *http.Request) {
	target := *req.URL
	target.Scheme, target.Host = "https", req.URL.Hostname()
	fmt.Fprintf(c, "HTTP/1.1 307 Temporary Redirect\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", target.String())
}

func (s *Server) connect(c net.Conn, br *bufio.Reader, target string) {
	host, port, err := net.SplitHostPort(target)
	host = strings.ToLower(host)
	if err != nil || port != "443" || !s.CA.Covers(host) {
		s.record(target, StageConnect, errors.New("refused: not a covered host on port 443"))
		io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
		return
	}
	io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	hello, err := peekClientHello(br)
	if err != nil {
		s.record(host, StageClient, err)
		return
	}

	var upstream *utls.UConn
	// The handshake reports only that it failed; stage says where.
	stage := StageClient
	client := tls.Server(c, &tls.Config{
		// Resumed sessions would carry a PSK bound to us into the mirrored hello.
		SessionTicketsDisabled: true,
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			if info.ServerName != "" && !strings.EqualFold(info.ServerName, host) {
				return nil, errors.New("proxy: SNI does not match the CONNECT host")
			}
			up, err := s.dialUpstream(info.Context(), host, hello, info.SupportedProtos)
			if err != nil {
				stage = StageDial
				if isVerifyError(err) {
					stage = StageVerify
				}
				return nil, err
			}
			upstream = up
			leaf, err := s.CA.Leaf(host, s.now())
			if err != nil {
				return nil, err
			}
			cfg := &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12, SessionTicketsDisabled: true}
			if p := up.ConnectionState().NegotiatedProtocol; p != "" {
				if !slices.Contains(info.SupportedProtos, p) {
					stage = StageALPN
					return nil, fmt.Errorf("proxy: server chose %q, which the browser did not offer", p)
				}
				cfg.NextProtos = []string{p}
			}
			return cfg, nil
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()
	err = client.HandshakeContext(ctx)
	if upstream != nil {
		defer upstream.Close()
	}
	if err != nil {
		s.record(host, stage, err)
		return
	}
	_ = c.SetDeadline(time.Time{})
	relay(client, upstream)
}

// dialUpstream connects to host with a ClientHello shaped like hello, falling
// back to a stock Chrome or Firefox shape, offering only the client's
// protocols, when hello cannot be mirrored.
func (s *Server) dialUpstream(ctx context.Context, host string, hello []byte, protos []string) (*utls.UConn, error) {
	dial := s.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	}
	verify := s.Verify
	if verify == nil {
		verify = TrustedOrRussian
	}
	cfg := &utls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		// Checked below against the system roots or the Russian root, for this host.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs utls.ConnectionState) error {
			if err := verify(cs.PeerCertificates, host); err != nil {
				return &verifyError{err}
			}
			s.checkPin(cs.PeerCertificates, host)
			return nil
		},
	}

	attempts := []bool{false}
	spec, specErr := (&utls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(hello)
	if specErr == nil {
		attempts = []bool{true, false}
	}
	for _, mirror := range attempts {
		raw, err := dial(ctx, "tcp", net.JoinHostPort(host, "443"))
		if err != nil {
			return nil, err
		}
		conn := utls.UClient(raw, cfg.Clone(), utls.HelloCustom)
		if mirror {
			if err := conn.ApplyPreset(spec); err != nil {
				raw.Close()
				continue
			}
		} else {
			fallback, err := fallbackSpec(hello, protos)
			if err == nil {
				err = conn.ApplyPreset(fallback)
			}
			if err != nil {
				raw.Close()
				return nil, err
			}
		}
		if err := conn.HandshakeContext(ctx); err != nil {
			raw.Close()
			if mirror && !isVerifyError(err) {
				continue
			}
			return nil, err
		}
		return conn, nil
	}
	return nil, errors.New("proxy: could not reach " + host)
}

// verifyError marks a server certificate that was rejected, as opposed to a
// server that could not be reached.
type verifyError struct{ err error }

func (e *verifyError) Error() string { return "server certificate rejected: " + e.err.Error() }
func (e *verifyError) Unwrap() error { return e.err }

func isVerifyError(err error) bool {
	var rejected *verifyError
	if errors.As(err, &rejected) {
		return true
	}
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &unknown) || errors.As(err, &hostname) || errors.As(err, &invalid)
}

// peekClientHello copies the first TLS record without consuming it; the copy
// outlives the handshake reading the same buffer.
func peekClientHello(br *bufio.Reader) ([]byte, error) {
	head, err := br.Peek(5)
	if err != nil {
		return nil, err
	}
	if head[0] != 0x16 {
		return nil, errors.New("proxy: expected a TLS handshake")
	}
	record, err := br.Peek(5 + int(head[3])<<8 | int(head[4]))
	return bytes.Clone(record), err
}

// TrustedOrRussian accepts a chain for host that either the system already
// trusts or that is issued under the Russian Trusted Root CA.
func TrustedOrRussian(chain []*x509.Certificate, host string) error {
	return TrustedOr(russianca.Default, chain, host)
}

// TrustedOr is TrustedOrRussian with the Russian side checked by russian.
func TrustedOr(russian *russianca.Verifier, chain []*x509.Certificate, host string) error {
	if len(chain) == 0 {
		return errors.New("proxy: server sent no certificate")
	}
	if systemTrusts(chain, host) {
		return nil
	}
	return russian.Verify(chain, host)
}

func systemTrusts(chain []*x509.Certificate, host string) bool {
	pool := x509.NewCertPool()
	for _, c := range chain[1:] {
		pool.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: pool})
	return err == nil
}

// checkPin logs a verified chain whose leaf key the signed list does not
// know. Chains the system trusts are never pinned, so they are skipped.
func (s *Server) checkPin(chain []*x509.Certificate, host string) {
	if s.Pinned == nil || len(chain) == 0 || s.Pinned(pins.SPKI(chain[0])) || systemTrusts(chain, host) {
		return
	}
	if _, seen := s.warned.LoadOrStore(host, true); !seen {
		s.record(host, StagePin, errors.New("leaf key is not in the signed list; allowed, the chain is valid under the Russian root"))
	}
}

func (s *Server) record(host string, stage Stage, err error) {
	s.Log.Add(Event{Time: s.now(), Host: host, Stage: stage, Err: err.Error()})
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go pipe(a, b)
	go pipe(b, a)
	<-done
	a.Close()
	b.Close()
	<-done
}

// bufferedConn reads through the bufio.Reader that parsed the CONNECT line,
// so a ClientHello sent right behind it is not lost.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
