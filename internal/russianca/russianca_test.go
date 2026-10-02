package russianca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

const rootSHA256 = "d26d2d0231b7c39f92cc738512ba54103519e4405d68b5bd703e9788ca8ecf31"

func TestEmbeddedRootIsTheMinistryRoot(t *testing.T) {
	sum := sha256.Sum256(mustParse(rootPEM).Raw)
	if got := hex.EncodeToString(sum[:]); got != rootSHA256 {
		t.Fatalf("embedded root sha256 %s", got)
	}
	sub := Default.Intermediates[0]
	if err := sub.CheckSignatureFrom(mustParse(rootPEM)); err != nil {
		t.Fatalf("sub CA is not issued by the root: %v", err)
	}
}

func TestVerify(t *testing.T) {
	root, rootKey := issue(t, nil, nil, "Test Root", true)
	leaf, _ := issue(t, root, rootKey, "bank.ru", false)
	fakeCA, fakeKey := issue(t, nil, nil, "Russian Trusted Sub CA", true)
	forged, _ := issue(t, fakeCA, fakeKey, "bank.ru", false)
	v := &Verifier{Roots: pool(root)}

	if err := v.Verify([]*x509.Certificate{leaf}, "bank.ru"); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
	if v.Verify([]*x509.Certificate{leaf}, "other.ru") == nil {
		t.Fatal("certificate accepted for a host it was not issued for")
	}
	if v.Verify([]*x509.Certificate{forged, fakeCA}, "bank.ru") == nil {
		t.Fatal("chain from a look-alike CA accepted")
	}
	if v.Verify(nil, "bank.ru") == nil {
		t.Fatal("empty chain accepted")
	}
}

func TestWithIntermediatesTakesOnlySubCAsOfTheRoot(t *testing.T) {
	root, rootKey := issue(t, nil, nil, "Test Root", true)
	sub, subKey := issue(t, root, rootKey, "Test Sub CA 2", true)
	leaf, _ := issue(t, sub, subKey, "bank.ru", false)
	rogue, rogueKey := issue(t, nil, nil, "Test Sub CA 2", true)
	forged, _ := issue(t, rogue, rogueKey, "bank.ru", false)
	notCA, _ := issue(t, root, rootKey, "other.ru", false)
	base := &Verifier{Roots: pool(root)}

	if base.Verify([]*x509.Certificate{leaf}, "bank.ru") == nil {
		t.Fatal("leaf verified without its Sub CA")
	}
	v := base.WithIntermediates([]*x509.Certificate{sub, rogue, notCA, sub})
	if len(v.Intermediates) != 1 || !v.Intermediates[0].Equal(sub) {
		t.Fatalf("kept %d intermediates", len(v.Intermediates))
	}
	if err := v.Verify([]*x509.Certificate{leaf}, "bank.ru"); err != nil {
		t.Fatalf("leaf under the listed Sub CA rejected: %v", err)
	}
	if v.Verify([]*x509.Certificate{forged}, "bank.ru") == nil {
		t.Fatal("leaf under a rogue CA from the list accepted")
	}
}

func TestPathFindsTheSubCA(t *testing.T) {
	root, rootKey := issue(t, nil, nil, "Test Root", true)
	sub, subKey := issue(t, root, rootKey, "Test Sub CA", true)
	leaf, _ := issue(t, sub, subKey, "bank.ru", false)
	// The server leaves the Sub CA out; the verifier knows it.
	v := &Verifier{Roots: pool(root), Intermediates: []*x509.Certificate{sub}}

	path, err := v.Path([]*x509.Certificate{leaf}, "bank.ru")
	if err != nil {
		t.Fatal(err)
	}
	if len(path) != 3 || !path[1].Equal(sub) || !path[2].Equal(root) {
		t.Fatalf("path %v", path)
	}
}

func issue(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, name string, ca bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  ca,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if !ca {
		tmpl.DNSNames = []string{name}
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

func TestIsMinistryCA(t *testing.T) {
	if !IsMinistryCA(mustParse(rootPEM)) || !IsMinistryCA(Default.Intermediates[0]) {
		t.Fatal("embedded Ministry certificates not recognised")
	}
	lookalike, _ := issue(t, nil, nil, "Russian Trusted Root CA", true)
	if IsMinistryCA(lookalike) {
		t.Fatal("certificate without the Ministry organisation recognised")
	}
}
