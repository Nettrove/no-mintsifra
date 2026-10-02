package localca

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestLeafVerifiesOnlyInsideConstraints(t *testing.T) {
	now := time.Now()
	ca, err := New([]string{"sberbank.ru", "vtb.ru"}, now)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)

	leaf, err := ca.Leaf("online.sberbank.ru", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "online.sberbank.ru", Roots: roots}); err != nil {
		t.Fatalf("leaf for a covered host does not verify: %v", err)
	}
	if again, _ := ca.Leaf("ONLINE.sberbank.ru", now); again != leaf {
		t.Error("leaf not reused")
	}
	for _, host := range []string{"google.com", "evilsberbank.ru", "127.0.0.1"} {
		if _, err := ca.Leaf(host, now); err == nil {
			t.Errorf("issued a leaf for %s", host)
		}
	}
}

func TestConstraintsBindEvenWithoutOurChecks(t *testing.T) {
	now := time.Now()
	ca, _ := New([]string{"sberbank.ru"}, now)
	installed, _ := x509.ParseCertificate(ca.Cert.Raw)
	roots := x509.NewCertPool()
	roots.AddCert(installed)

	// Bypass Covers to model a stolen key signing for another site.
	ca.Cert.PermittedDNSDomains = append(ca.Cert.PermittedDNSDomains, "google.com")
	rogue, err := ca.Leaf("www.google.com", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rogue.Leaf.Verify(x509.VerifyOptions{DNSName: "www.google.com", Roots: roots}); err == nil {
		t.Fatal("a leaf outside the signed name constraints verified")
	}
}

func TestSaveLoad(t *testing.T) {
	dir := t.TempDir()
	ca, _ := New([]string{"vtb.ru"}, time.Now())
	if err := ca.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Cert.Equal(ca.Cert) || !got.key.Equal(ca.key) {
		t.Fatal("round trip changed the CA")
	}
	if err := Remove(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("load after remove succeeded")
	}
}
