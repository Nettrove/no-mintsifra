package probe

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Nettrove/no-mintsifra/internal/pins"
	"github.com/Nettrove/no-mintsifra/internal/russianca"
)

func TestObserveReadsServerLeaf(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, err := Observe(ctx, u.Host)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 leaf, got %d", len(got))
	}

	want := srv.Certificate()
	if got[0].SPKI != pins.SPKI(want) || got[0].Fingerprint != pins.Fingerprint(want) {
		t.Errorf("observation does not match the server certificate: %+v", got[0])
	}
	if got[0].Trusted {
		t.Error("self-signed test certificate reported as trusted")
	}
}

func TestObserveUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Observe(ctx, "127.0.0.1:1"); err == nil {
		t.Fatal("expected an error for a closed port")
	}
}

func TestObserveRequiresChainToRussianRoot(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	defer func(v *russianca.Verifier) { russian = v }(russian)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	russian = &russianca.Verifier{Roots: roots}
	if got, err := Observe(ctx, u.Host); err != nil || !got[0].RussianCA {
		t.Fatalf("chain to the configured root not recognised: %v %+v", err, got)
	}
	russian = &russianca.Verifier{Roots: x509.NewCertPool()}
	if got, err := Observe(ctx, u.Host); err != nil || got[0].RussianCA {
		t.Fatalf("chain to an unknown root recognised: %v %+v", err, got)
	}
}

func TestSplitAddr(t *testing.T) {
	cases := map[string][2]string{
		"example.ru":      {"example.ru", "443"},
		"example.ru:8443": {"example.ru", "8443"},
	}
	for in, want := range cases {
		if h, p := splitAddr(in); h != want[0] || p != want[1] {
			t.Errorf("splitAddr(%q) = %s,%s", in, h, p)
		}
	}
}
