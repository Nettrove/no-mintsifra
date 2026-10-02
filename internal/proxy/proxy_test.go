package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/Nettrove/no-mintsifra/internal/localca"
)

// rig runs a real TLS server standing in for every bank, a proxy in front of
// it and a client that trusts only the local CA. A nil verify trusts exactly
// the stand-in server.
type rig struct {
	proxy  *Server
	client *http.Client
	addr   string
	// hellos receives the cipher suites of every ClientHello the bank sees.
	hellos chan []uint16
	// brokenPAC makes the PAC builder panic.
	brokenPAC *atomic.Bool
	// unpinned makes every leaf key unknown to the list.
	unpinned *atomic.Bool
}

func newRig(t *testing.T, verify func([]*x509.Certificate, string) error) *rig {
	t.Helper()
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "bank:"+r.Host+":"+r.Proto)
	}))
	up.EnableHTTP2 = true
	hellos := make(chan []uint16, 8)
	up.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		hellos <- h.CipherSuites
		return nil, nil
	}}
	up.StartTLS()
	t.Cleanup(up.Close)

	ca, err := localca.New([]string{"example.com"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if verify == nil {
		verify = func(chain []*x509.Certificate, host string) error {
			roots := x509.NewCertPool()
			roots.AddCert(up.Certificate())
			_, err := chain[0].Verify(x509.VerifyOptions{DNSName: host, Roots: roots})
			return err
		}
	}
	upAddr := up.Listener.Addr().String()
	brokenPAC, unpinned := new(atomic.Bool), new(atomic.Bool)
	s := &Server{
		Pinned: func(string) bool { return !unpinned.Load() },
		CA:     ca,
		PAC: func() []byte {
			if brokenPAC.Load() {
				panic("broken script")
			}
			return PAC("127.0.0.1:1", []string{"example.com"}, Direct)
		},
		Verify: verify,
		Log:    NewLog("", 16, 0),
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upAddr)
		},
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go s.Serve(l)

	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	proxyURL, _ := url.Parse("http://" + l.Addr().String())
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: roots}}
	t.Cleanup(tr.CloseIdleConnections)
	return &rig{proxy: s, hellos: hellos, brokenPAC: brokenPAC, unpinned: unpinned, client: &http.Client{Transport: tr, Timeout: 10 * time.Second}, addr: l.Addr().String()}
}

// wantEvent waits for the proxy to log a failure at stage for host.
func (r *rig) wantEvent(t *testing.T, stage Stage, host string) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		for _, e := range r.proxy.Log.Recent() {
			if e.Stage == stage && e.Host == host {
				return
			}
		}
	}
	t.Fatalf("no %s event for %s in %v", stage, host, r.proxy.Log.Recent())
}

func TestRelaysCoveredHostOverHTTP2(t *testing.T) {
	r := newRig(t, nil)

	resp, err := r.client.Get("https://www.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "bank:www.example.com:HTTP/2.0" {
		t.Fatalf("got %q", body)
	}
	if issuer := resp.TLS.PeerCertificates[0].Issuer.CommonName; issuer != "no-mintsifra local CA" {
		t.Fatalf("client saw issuer %q", issuer)
	}
}

func TestRefusesUncoveredHost(t *testing.T) {
	r := newRig(t, nil)

	if _, err := r.client.Get("https://google.com/"); err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("uncovered host was relayed: %v", err)
	}
	r.wantEvent(t, StageConnect, "google.com:443")
}

func TestDropsUpstreamThatFailsVerification(t *testing.T) {
	r := newRig(t, func([]*x509.Certificate, string) error { return errors.New("not the bank") })
	if resp, err := r.client.Get("https://www.example.com/"); err == nil {
		resp.Body.Close()
		t.Fatal("relayed to a server that failed verification")
	}
	r.wantEvent(t, StageVerify, "www.example.com")
}

func TestSurvivesAPanicInOneConnection(t *testing.T) {
	r := newRig(t, nil)
	r.brokenPAC.Store(true)
	if resp, err := http.Get("http://" + r.addr + PACPath); err == nil {
		resp.Body.Close()
	}
	r.brokenPAC.Store(false)

	resp, err := r.client.Get("https://www.example.com/")
	if err != nil {
		t.Fatalf("proxy did not survive: %v", err)
	}
	resp.Body.Close()
	for _, e := range r.proxy.Log.Recent() {
		if e.Stage == StageRecovered && e.Err == "broken script" {
			return
		}
	}
	t.Fatalf("panic not logged: %v", r.proxy.Log.Recent())
}

func TestUnpinnedLeafIsLoggedOnceAndAllowed(t *testing.T) {
	r := newRig(t, nil)
	r.unpinned.Store(true)
	for range 2 {
		resp, err := r.client.Get("https://www.example.com/")
		if err != nil {
			t.Fatalf("unpinned leaf blocked: %v", err)
		}
		resp.Body.Close()
	}
	n := 0
	for _, e := range r.proxy.Log.Recent() {
		if e.Stage == StagePin && e.Host == "www.example.com" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d pin warnings, want 1: %v", n, r.proxy.Log.Recent())
	}
}

func TestServesPAC(t *testing.T) {
	r := newRig(t, nil)
	resp, err := http.Get("http://" + r.addr + PACPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.Header.Get("Content-Type") != "application/x-ns-proxy-autoconfig" || !strings.Contains(string(body), `["example.com"]`) {
		t.Fatalf("bad PAC response: %s %q", resp.Header.Get("Content-Type"), body)
	}
}

func TestBankSeesTheBrowserClientHello(t *testing.T) {
	r := newRig(t, nil)

	// A Firefox-shaped hello stands in for the browser; the fallback would be Chrome-shaped.
	uc := utls.UClient(nil, &utls.Config{ServerName: "www.example.com"}, utls.HelloFirefox_Auto)
	if err := uc.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	body := uc.HandshakeState.Hello.Raw
	hello := append([]byte{0x16, 0x03, 0x01, byte(len(body) >> 8), byte(len(body))}, body...)
	want := uc.HandshakeState.Hello.CipherSuites

	up, err := r.proxy.dialUpstream(context.Background(), "www.example.com", hello, nil)
	if err != nil {
		t.Fatal(err)
	}
	up.Close()
	got := <-r.hellos
	if !slices.Equal(stripGREASE(got), stripGREASE(want)) {
		t.Fatalf("bank saw cipher suites %x, browser offered %x", got, want)
	}
}

func TestUnreadableHelloDialsOnce(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	var dials atomic.Int32
	s := &Server{Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, l.Addr().String())
	}}

	if _, err := s.dialUpstream(context.Background(), "www.example.com", []byte{0x16, 0x03, 0x01, 0x00, 0x01, 0xff}, nil); err == nil {
		t.Fatal("handshake with a closed server succeeded")
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("dialled %d times for one fallback attempt", n)
	}
}

func TestFallbackOffersOnlyTheClientsProtocols(t *testing.T) {
	r := newRig(t, nil)
	unreadable := []byte{0x16, 0x03, 0x01, 0x00, 0x01, 0xff}
	// The stand-in bank speaks only h2 over ALPN and falls back to none.
	for _, tc := range []struct {
		offered []string
		want    string
	}{
		{[]string{"h2", "http/1.1"}, "h2"},
		{[]string{"http/1.1"}, ""},
		{nil, ""},
	} {
		up, err := r.proxy.dialUpstream(context.Background(), "www.example.com", unreadable, tc.offered)
		if err != nil {
			t.Fatal(err)
		}
		<-r.hellos
		if got := up.ConnectionState().NegotiatedProtocol; got != tc.want {
			t.Errorf("client offered %q, server chose %q, want %q", tc.offered, got, tc.want)
		}
		up.Close()
	}
}

func stripGREASE(suites []uint16) []uint16 {
	return slices.DeleteFunc(slices.Clone(suites), func(s uint16) bool { return s&0x0f0f == 0x0a0a })
}

func TestUpgradesPlainHTTPForCoveredHosts(t *testing.T) {
	r := newRig(t, nil)
	proxyURL, _ := url.Parse("http://" + r.addr)
	client := &http.Client{
		Transport:     &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	resp, err := client.Get("http://login.example.com/sms?code=1&next=%2Fhome")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect || resp.Header.Get("Location") != "https://login.example.com/sms?code=1&next=%2Fhome" {
		t.Fatalf("got %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	resp, err = client.Get("http://google.com/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("uncovered plain HTTP got %d", resp.StatusCode)
	}
}
