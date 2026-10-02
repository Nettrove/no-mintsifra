package pins

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

func sample() *Set {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	other := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	return &Set{
		Schema:    SchemaVersion,
		Generated: now,
		Sites: []Site{
			{Name: "Bank", Hosts: []string{"bank.example.ru", "*.bank.example.ru"}, Pins: []Pin{
				{SPKI: key, Certs: []string{strings.Repeat("a", 64)}, NotAfter: now.Add(24 * time.Hour)},
				{SPKI: other, NotAfter: now.Add(-time.Hour)},
			}},
		},
	}
}

func TestSignOpenRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data, err := sample().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	set, err := Open(data, Sign(data, priv), pub)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if set.Sites[0].Name != "Bank" {
		t.Fatalf("unexpected site %q", set.Sites[0].Name)
	}
}

func TestOpenRejectsTamperedPayload(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data, _ := sample().Marshal()
	sig := Sign(data, priv)
	tampered := []byte(strings.Replace(string(data), "Bank", "Evil", 1))
	if _, err := Open(tampered, sig, pub); err != ErrBadSignature {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestOpenRejectsForeignKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	data, _ := sample().Marshal()
	if _, err := Open(data, Sign(data, priv), otherPub); err != ErrBadSignature {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestSPKIsSkipsExpired(t *testing.T) {
	got := sample().SPKIs(now)
	if len(got) != 1 {
		t.Fatalf("want 1 active pin, got %d", len(got))
	}
}

func TestParseRejectsCommandLineInjection(t *testing.T) {
	for _, spki := range []string{"AAAA,--disable-web-security", "not base64!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		s := sample()
		s.Sites[0].Pins[0].SPKI = spki
		data, _ := s.Marshal()
		if _, err := Parse(data); err == nil {
			t.Errorf("accepted spki %q", spki)
		}
	}
}

func TestParseRejectsBadHostAndSchema(t *testing.T) {
	s := sample()
	s.Sites[0].Hosts = []string{"bad host"}
	data, _ := s.Marshal()
	if _, err := Parse(data); err == nil {
		t.Error("accepted invalid host")
	}
	s = sample()
	s.Schema = 99
	data, _ = s.Marshal()
	if _, err := Parse(data); err == nil {
		t.Error("accepted unknown schema")
	}
}

func TestMarshalIsDeterministic(t *testing.T) {
	a, _ := sample().Marshal()
	b, _ := sample().Marshal()
	if string(a) != string(b) {
		t.Fatal("marshal output differs between runs")
	}
}

func TestSchemaV2CarriesIntermediates(t *testing.T) {
	ca := testCA(t, true)
	s := sample()
	s.Schema = SchemaV2
	s.Intermediates = []string{base64.StdEncoding.EncodeToString(ca.Raw)}
	data, _ := s.Marshal()
	got, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if certs := got.IntermediateCerts(); len(certs) != 1 || !certs[0].Equal(ca) {
		t.Fatalf("intermediates %v", certs)
	}

	v1, _ := got.V1().Marshal()
	if strings.Contains(string(v1), "intermediates") || !strings.Contains(string(v1), `"schema": 1`) {
		t.Fatalf("v1 output:\n%s", v1)
	}
	if _, err := Parse(v1); err != nil {
		t.Fatal(err)
	}
}

func TestParseRejectsBadIntermediates(t *testing.T) {
	leaf := testCA(t, false)
	for _, raw := range []string{"not base64!", base64.StdEncoding.EncodeToString([]byte("junk")), base64.StdEncoding.EncodeToString(leaf.Raw)} {
		s := sample()
		s.Schema = SchemaV2
		s.Intermediates = []string{raw}
		data, _ := s.Marshal()
		if _, err := Parse(data); err == nil {
			t.Errorf("accepted intermediate %.20q", raw)
		}
	}
	s := sample()
	s.Intermediates = []string{base64.StdEncoding.EncodeToString(testCA(t, true).Raw)}
	data, _ := s.Marshal()
	if _, err := Parse(data); err == nil {
		t.Error("schema 1 accepted intermediates")
	}
}

func testCA(t *testing.T, isCA bool) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Russian Trusted Sub CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestOpenWithHonoursKeyWindows(t *testing.T) {
	oldPub, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	keys := []Key{{Public: newPub}, {Public: oldPub, NotAfter: now.Add(-time.Hour)}}

	data, _ := sample().Marshal() // generated at now
	if _, err := OpenWith(data, Sign(data, newPriv), keys); err != nil {
		t.Fatalf("current key rejected: %v", err)
	}
	if _, err := OpenWith(data, Sign(data, oldPriv), keys); err != ErrRetiredKey {
		t.Fatalf("set signed by a retired key after retirement: %v", err)
	}
	early := sample()
	early.Generated = now.Add(-2 * time.Hour)
	data, _ = early.Marshal()
	if _, err := OpenWith(data, Sign(data, oldPriv), keys); err != nil {
		t.Fatalf("set signed before retirement rejected: %v", err)
	}
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := OpenWith(data, Sign(data, stranger), keys); err != ErrBadSignature {
		t.Fatalf("foreign key: %v", err)
	}
}
