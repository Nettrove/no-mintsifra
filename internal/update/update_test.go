package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nettrove/no-mintsifra/internal/pins"
)

var epoch = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

type fixture struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{pub, priv}
}

func (f fixture) bundle(t *testing.T, generated time.Time) Bundle {
	t.Helper()
	set := &pins.Set{
		Schema:    pins.SchemaVersion,
		Generated: generated,
		Sites: []pins.Site{{Name: "Bank", Hosts: []string{"bank.ru"}, Pins: []pins.Pin{
			{SPKI: base64.StdEncoding.EncodeToString(make([]byte, 32)), NotAfter: epoch.Add(240 * time.Hour)},
		}}},
	}
	data, err := set.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return Bundle{Data: data, Sig: pins.Sign(data, f.priv)}
}

func serve(b Bundle) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/pins.v2.json"):
			w.Write(b.Data)
		case strings.HasSuffix(r.URL.Path, "/pins.v2.json.sig"):
			w.Write(b.Sig)
		default:
			http.NotFound(w, r)
		}
	}))
}

func (f fixture) store(t *testing.T, fallback Bundle, sources ...string) *Store {
	return &Store{Dir: t.TempDir(), Sources: sources, Keys: []pins.Key{{Public: f.pub}}, Fallback: fallback}
}

func TestRefreshAcceptsNewerSetAndCachesIt(t *testing.T) {
	f := newFixture(t)
	srv := serve(f.bundle(t, epoch.Add(time.Hour)))
	defer srv.Close()

	st := f.store(t, f.bundle(t, epoch), srv.URL)
	set, changed, err := st.Refresh(context.Background())
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if !set.Generated.Equal(epoch.Add(time.Hour)) {
		t.Fatalf("generated %v", set.Generated)
	}

	cur, err := st.Current()
	if err != nil || !cur.Generated.Equal(epoch.Add(time.Hour)) {
		t.Fatalf("cache not used: %v %v", cur, err)
	}
}

func TestRefreshRejectsForgedSignature(t *testing.T) {
	f, attacker := newFixture(t), newFixture(t)
	srv := serve(attacker.bundle(t, epoch.Add(time.Hour)))
	defer srv.Close()

	st := f.store(t, f.bundle(t, epoch), srv.URL)
	set, changed, err := st.Refresh(context.Background())
	if err == nil || changed {
		t.Fatalf("forged set accepted: changed=%v err=%v", changed, err)
	}
	if !set.Generated.Equal(epoch) {
		t.Fatal("local set must remain usable after a failed refresh")
	}
}

func TestRefreshRejectsRollback(t *testing.T) {
	f := newFixture(t)
	srv := serve(f.bundle(t, epoch.Add(-time.Hour)))
	defer srv.Close()

	_, changed, err := f.store(t, f.bundle(t, epoch), srv.URL).Refresh(context.Background())
	if err == nil || changed {
		t.Fatalf("rollback accepted: changed=%v err=%v", changed, err)
	}
}

func TestRefreshFallsThroughToNextSource(t *testing.T) {
	f := newFixture(t)
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	live := serve(f.bundle(t, epoch.Add(time.Hour)))
	defer live.Close()

	_, changed, err := f.store(t, f.bundle(t, epoch), dead.URL, live.URL).Refresh(context.Background())
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
}

func TestRefreshNoChangeWhenUpToDate(t *testing.T) {
	f := newFixture(t)
	b := f.bundle(t, epoch)
	srv := serve(b)
	defer srv.Close()

	_, changed, err := f.store(t, b, srv.URL).Refresh(context.Background())
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
}

func TestRefreshRejectsOversizedBody(t *testing.T) {
	f := newFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(make([]byte, maxBody+10))
	}))
	defer srv.Close()

	if _, changed, err := f.store(t, f.bundle(t, epoch), srv.URL).Refresh(context.Background()); err == nil || changed {
		t.Fatalf("oversized body accepted: changed=%v err=%v", changed, err)
	}
}

func TestCurrentIgnoresTamperedCache(t *testing.T) {
	f := newFixture(t)
	st := f.store(t, f.bundle(t, epoch))
	if err := st.writeCache(Bundle{Data: []byte(`{"schema":1}`), Sig: []byte("AAAA")}); err != nil {
		t.Fatal(err)
	}
	cur, err := st.Current()
	if err != nil || !cur.Generated.Equal(epoch) {
		t.Fatalf("tampered cache was trusted: %v %v", cur, err)
	}
}

func TestSourcesFromEnv(t *testing.T) {
	if got := SourcesFromEnv(" https://a.example/x/ , ,https://b.example "); len(got) != 2 || got[0] != "https://a.example/x" {
		t.Fatalf("got %v", got)
	}
	if got := SourcesFromEnv(""); len(got) != len(DefaultSources) {
		t.Fatalf("empty value must fall back to defaults, got %v", got)
	}
}

func TestCurrentReadsTheLegacyCache(t *testing.T) {
	f := newFixture(t)
	st := f.store(t, f.bundle(t, epoch))
	newer := f.bundle(t, epoch.Add(time.Hour))
	if err := os.WriteFile(filepath.Join(st.Dir, legacyFile), newer.Data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(st.Dir, legacyFile+".sig"), newer.Sig, 0o644); err != nil {
		t.Fatal(err)
	}
	if cur, err := st.Current(); err != nil || !cur.Generated.Equal(epoch.Add(time.Hour)) {
		t.Fatalf("legacy cache ignored: %v %v", cur, err)
	}
}

func TestRefreshRejectsSetSignedByRetiredKey(t *testing.T) {
	f := newFixture(t)
	st := f.store(t, f.bundle(t, epoch))
	// The key was retired an hour after the embedded set was made.
	st.Keys[0].NotAfter = epoch.Add(time.Hour)
	srv := serve(f.bundle(t, epoch.Add(2*time.Hour)))
	defer srv.Close()
	st.Sources = []string{srv.URL}

	set, changed, err := st.Refresh(context.Background())
	if err == nil || changed || !set.Generated.Equal(epoch) {
		t.Fatalf("set signed after retirement accepted: changed=%v err=%v", changed, err)
	}
}
