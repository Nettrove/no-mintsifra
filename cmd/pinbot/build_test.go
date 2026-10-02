package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nettrove/no-mintsifra/internal/pins"
	"github.com/Nettrove/no-mintsifra/internal/probe"
)

var today = time.Date(2026, 10, 2, 15, 0, 0, 0, time.UTC)

func russian(spki, fp string) probe.Observation {
	return probe.Observation{SPKI: spki, Fingerprint: fp, RussianCA: true, NotAfter: today.Add(90 * 24 * time.Hour)}
}

func fixed(m map[string][]probe.Observation) observer {
	return func(_ context.Context, addr string) ([]probe.Observation, error) {
		o, ok := m[addr]
		if !ok {
			return nil, errors.New("unreachable")
		}
		return o, nil
	}
}

func noExpansion(context.Context, string) []string { return nil }

func TestBuildPinsOnlyRussianChainsNotTrustedBySystem(t *testing.T) {
	entries := []entry{
		{Name: "Bank", Hosts: []string{"bank.ru", "www.bank.ru"}},
		{Name: "Gov", Hosts: []string{"gov.ru"}},
		{Name: "SelfSigned", Hosts: []string{"junk.ru"}},
	}
	trusted := russian("keyG", "fpG")
	trusted.Trusted = true
	set, _ := build(context.Background(), entries, nil, today, fixed(map[string][]probe.Observation{
		"bank.ru":     {russian("keyA", "fpA")},
		"www.bank.ru": {russian("keyA", "fpA")},
		"gov.ru":      {trusted},
		"junk.ru":     {{SPKI: "keyJ", Fingerprint: "fpJ"}},
	}), noExpansion)

	if len(set.Sites) != 1 || set.Sites[0].Name != "Bank" {
		t.Fatalf("want only Bank, got %+v", set.Sites)
	}
	if got := set.Sites[0].Pins; len(got) != 1 || got[0].SPKI != "keyA" {
		t.Fatalf("pins not deduplicated: %+v", got)
	}
}

func TestBuildEnumeratesSubdomainsOfRussianDomains(t *testing.T) {
	entries := []entry{{Name: "Alfa", Domains: []string{"alfa.ru"}}}
	expanded := 0
	expand := func(_ context.Context, domain string) []string {
		expanded++
		return []string{"alfa.ru", "web.alfa.ru", "dead.alfa.ru"}
	}
	set, _ := build(context.Background(), entries, nil, today, fixed(map[string][]probe.Observation{
		"alfa.ru":     {russian("keyApex", "fp1")},
		"web.alfa.ru": {russian("keyWeb", "fp2")},
	}), expand)

	if expanded != 1 {
		t.Fatalf("expanded %d times", expanded)
	}
	site := set.Sites[0]
	if !slices.Equal(site.Hosts, []string{"alfa.ru", "web.alfa.ru"}) || len(site.Pins) != 2 {
		t.Fatalf("hosts=%v pins=%d", site.Hosts, len(site.Pins))
	}
}

func TestBuildSkipsEnumerationForDomainsOutsideRussianCA(t *testing.T) {
	entries := []entry{{Name: "Shop", Domains: []string{"shop.ru"}}}
	expand := func(context.Context, string) []string {
		t.Fatal("enumerated a domain that is not on the Russian Trusted CA")
		return nil
	}
	set, _ := build(context.Background(), entries, nil, today, fixed(map[string][]probe.Observation{
		"shop.ru": {{SPKI: "k", Fingerprint: "f", Trusted: true}},
	}), expand)
	if len(set.Sites) != 0 {
		t.Fatalf("unexpected sites: %+v", set.Sites)
	}
}

func TestBuildRemembersHostsFromPreviousRun(t *testing.T) {
	prev := &pins.Set{Sites: []pins.Site{{Name: "Alfa", Hosts: []string{"secret.alfa.ru"}}}}
	entries := []entry{{Name: "Alfa", Domains: []string{"alfa.ru"}}}
	set, _ := build(context.Background(), entries, prev, today, fixed(map[string][]probe.Observation{
		"alfa.ru":        {russian("k1", "f1")},
		"secret.alfa.ru": {russian("k2", "f2")},
	}), noExpansion)

	if !slices.Contains(set.Sites[0].Hosts, "secret.alfa.ru") {
		t.Fatalf("host from previous run lost: %v", set.Sites[0].Hosts)
	}
}

func TestBuildWarnsWhenSiteLosesAllPins(t *testing.T) {
	prev := &pins.Set{Sites: []pins.Site{{Name: "Bank", Pins: []pins.Pin{{SPKI: "old", NotAfter: today.Add(-time.Hour), LastSeen: today}}}}}
	_, warns := build(context.Background(), []entry{{Name: "Bank", Hosts: []string{"bank.ru"}}}, prev, today, fixed(nil), noExpansion)
	if len(warns) != 1 {
		t.Fatalf("warnings = %v", warns)
	}
}

func TestBuildKeepsRotatedKeyWithinRetention(t *testing.T) {
	old := pins.Pin{SPKI: "keyOld", Certs: []string{"fpOld"}, NotAfter: today.Add(30 * 24 * time.Hour), LastSeen: today.Add(-5 * 24 * time.Hour)}
	prev := &pins.Set{Sites: []pins.Site{{Name: "Bank", Pins: []pins.Pin{old}}}}

	set, _ := build(context.Background(), []entry{{Name: "Bank", Hosts: []string{"bank.ru"}}}, prev, today, fixed(map[string][]probe.Observation{
		"bank.ru": {russian("keyNew", "fpNew")},
	}), noExpansion)
	if got := len(set.Sites[0].Pins); got != 2 {
		t.Fatalf("want rotated and new key, got %d pins", got)
	}
}

func TestBuildDropsKeyAfterRetention(t *testing.T) {
	stale := pins.Pin{SPKI: "keyOld", Certs: []string{"fpOld"}, NotAfter: today.Add(300 * 24 * time.Hour), LastSeen: today.Add(-22 * 24 * time.Hour)}
	prev := &pins.Set{Sites: []pins.Site{{Name: "Bank", Pins: []pins.Pin{stale}}}}

	set, _ := build(context.Background(), []entry{{Name: "Bank", Hosts: []string{"bank.ru"}}}, prev, today, fixed(map[string][]probe.Observation{
		"bank.ru": {russian("keyNew", "fpNew")},
	}), noExpansion)
	if got := set.Sites[0].Pins; len(got) != 1 || got[0].SPKI != "keyNew" {
		t.Fatalf("stale key survived: %+v", got)
	}
}

func TestMergeCapsCertHistory(t *testing.T) {
	certs := []string{"1", "2", "3", "4", "5", "6", "7", "8"}
	prev := []pins.Pin{{SPKI: "k", Certs: certs, NotAfter: today.Add(time.Hour), LastSeen: today}}
	got := mergePins([]probe.Observation{russian("k", "new")}, prev, today)
	if len(got[0].Certs) != maxCertsPerPin || got[0].Certs[0] != "new" {
		t.Fatalf("cert history not capped newest-first: %v", got[0].Certs)
	}
}

func subCA(t *testing.T, name string, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             today.Add(-time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestBuildKeepsUnexpiredIntermediates(t *testing.T) {
	current := subCA(t, "Sub CA 2", today.Add(365*24*time.Hour))
	older := subCA(t, "Sub CA 1", today.Add(30*24*time.Hour))
	expired := subCA(t, "Sub CA 0", today.Add(-time.Hour))
	prev := &pins.Set{Schema: pins.SchemaV2, Intermediates: []string{
		base64.StdEncoding.EncodeToString(older.Raw),
		base64.StdEncoding.EncodeToString(expired.Raw),
	}}
	obs := russian("keyA", "fpA")
	obs.Intermediates = []*x509.Certificate{current}

	set, _ := build(context.Background(), []entry{{Name: "Bank", Hosts: []string{"bank.ru"}}}, prev, today,
		fixed(map[string][]probe.Observation{"bank.ru": {obs}}), noExpansion)

	if set.Schema != pins.SchemaV2 {
		t.Fatalf("schema %d", set.Schema)
	}
	var names []string
	for _, c := range set.IntermediateCerts() {
		names = append(names, c.Subject.CommonName)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"Sub CA 1", "Sub CA 2"}) {
		t.Fatalf("intermediates %v", names)
	}
	if v1 := set.V1(); v1.Schema != pins.SchemaVersion || len(v1.Intermediates) != 0 {
		t.Fatalf("v1 copy %+v", v1)
	}
}

func TestExportWritesRawChainsOnly(t *testing.T) {
	ca := subCA(t, "Russian Trusted Sub CA", today.Add(time.Hour))
	obs := russian("keyA", "fpA")
	obs.Chain = []*x509.Certificate{ca}
	sc := &scanner{seen: map[string][]probe.Observation{"bank.ru": {obs}, "dead.ru": nil}}

	var buf bytes.Buffer
	if err := sc.export(&buf, today); err != nil {
		t.Fatal(err)
	}
	var got observations
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Hosts) != 1 || len(got.Hosts["bank.ru"]) != 1 || got.Hosts["bank.ru"][0][0] != base64.StdEncoding.EncodeToString(ca.Raw) {
		t.Fatalf("exported %+v", got)
	}
	if strings.Contains(buf.String(), "keyA") || strings.Contains(buf.String(), "RussianCA") {
		t.Fatal("verdicts leaked into the observations")
	}
}

func TestAddJudgesExternalChainsItself(t *testing.T) {
	// A chain under a look-alike "Russian" CA, as a hostile probe might send.
	fake := subCA(t, "Russian Trusted Root CA", today.Add(time.Hour))
	sc := &scanner{}
	sc.add(map[string][][]*x509.Certificate{
		"bank.ru":     {{fake}},
		"Bad Host!":   {{fake}},
		"www.bank.ru": {{fake}, {fake}},
	})
	if _, ok := sc.seen["Bad Host!"]; ok {
		t.Fatal("invalid host name accepted")
	}
	if n := len(sc.seen["www.bank.ru"]); n != 1 {
		t.Fatalf("duplicate chain kept: %d", n)
	}
	for host, obs := range sc.seen {
		for _, o := range obs {
			if o.RussianCA || pinnable(o) {
				t.Fatalf("%s: forged chain judged Russian", host)
			}
		}
	}
	set, _ := assemble([]entry{{Name: "Bank", Domains: []string{"bank.ru"}}}, nil, today, sc)
	if len(set.Sites) != 0 {
		t.Fatalf("forged observations produced pins: %+v", set.Sites)
	}
}

func TestObservationsRoundTrip(t *testing.T) {
	ca := subCA(t, "Some CA", today.Add(time.Hour))
	obs := probe.FromChain("bank.ru", []*x509.Certificate{ca})
	src := &scanner{seen: map[string][]probe.Observation{"bank.ru": {obs}}}
	path := filepath.Join(t.TempDir(), "obs.json")
	f, _ := os.Create(path)
	if err := src.export(f, today); err != nil {
		t.Fatal(err)
	}
	f.Close()

	external, err := readObservations(path, today.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	dst := &scanner{}
	dst.add(external)
	if got := dst.seen["bank.ru"]; len(got) != 1 || got[0].Fingerprint != obs.Fingerprint {
		t.Fatalf("round trip lost the chain: %+v", got)
	}
	if _, err := readObservations(path, today.Add(maxObservationAge+time.Minute)); err == nil {
		t.Fatal("stale observations accepted")
	}
	if _, err := readObservations(path, today.Add(-2*clockSkew)); err == nil {
		t.Fatal("observations from the future accepted")
	}
	_ = os.WriteFile(path, []byte(`{"hosts":{}}`), 0o644)
	if _, err := readObservations(path, today); err == nil {
		t.Fatal("observations without a generation time accepted")
	}
	_ = os.WriteFile(path, []byte("{not json"), 0o644)
	if _, err := readObservations(path, today); err == nil {
		t.Fatal("malformed observations accepted")
	}
}
