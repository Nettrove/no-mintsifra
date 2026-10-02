// Package update keeps the local pin set fresh without trusting the transport:
// every download must carry a valid signature and may not roll the set back.
package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Nettrove/no-mintsifra/internal/pins"
)

const (
	// pinsFile is the schema 2 list; pins.json keeps schema 1 for older clients.
	pinsFile = "pins.v2.json"
	sigFile  = pinsFile + ".sig"
	// legacyFile is the cache older versions wrote, still good until replaced.
	legacyFile = "pins.json"
	maxBody    = 1 << 20
)

var DefaultSources = []string{
	"https://raw.githubusercontent.com/Nettrove/no-mintsifra/pins",
	"https://cdn.jsdelivr.net/gh/Nettrove/no-mintsifra@pins",
}

type Bundle struct {
	Data, Sig []byte
}

type Store struct {
	Dir     string
	Sources []string
	// Keys verify the signatures, each within its validity window.
	Keys     []pins.Key
	Fallback Bundle
	Client   *http.Client
}

// SourcesFromEnv returns the comma-separated mirrors in value, or the defaults.
func SourcesFromEnv(value string) []string {
	var out []string
	for _, s := range strings.Split(value, ",") {
		if s = strings.TrimRight(strings.TrimSpace(s), "/"); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return DefaultSources
	}
	return out
}

// Current returns the newest verified set among the cache and the embedded snapshot.
func (s *Store) Current() (*pins.Set, error) {
	best, err := pins.OpenWith(s.Fallback.Data, s.Fallback.Sig, s.Keys)
	if err != nil {
		return nil, fmt.Errorf("embedded snapshot: %w", err)
	}
	for _, name := range []string{pinsFile, legacyFile} {
		if cached, err := s.readCache(name); err == nil && cached.Generated.After(best.Generated) {
			best = cached
		}
	}
	return best, nil
}

// Refresh asks each source in turn and stores the first newer, correctly
// signed set. The returned set is always usable, even when err is not nil.
func (s *Store) Refresh(ctx context.Context) (set *pins.Set, changed bool, err error) {
	current, err := s.Current()
	if err != nil {
		return nil, false, err
	}

	var failures []error
	for _, src := range s.Sources {
		bundle, err := s.fetch(ctx, src)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", src, err))
			continue
		}
		next, err := pins.OpenWith(bundle.Data, bundle.Sig, s.Keys)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", src, err))
			continue
		}
		switch {
		case next.Generated.Before(current.Generated):
			failures = append(failures, fmt.Errorf("%s: set is older than the local one", src))
			continue
		case next.Generated.Equal(current.Generated):
			return current, false, nil
		}
		if err := s.writeCache(bundle); err != nil {
			return next, true, fmt.Errorf("cache update: %w", err)
		}
		return next, true, nil
	}
	return current, false, errors.Join(failures...)
}

func (s *Store) fetch(ctx context.Context, base string) (Bundle, error) {
	data, err := s.get(ctx, base+"/"+pinsFile)
	if err != nil {
		return Bundle{}, err
	}
	sig, err := s.get(ctx, base+"/"+sigFile)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{Data: data, Sig: sig}, nil
}

func (s *Store) get(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBody {
		return nil, errors.New("response too large")
	}
	return body, nil
}

func (s *Store) readCache(name string) (*pins.Set, error) {
	data, err := os.ReadFile(filepath.Join(s.Dir, name))
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(filepath.Join(s.Dir, name+".sig"))
	if err != nil {
		return nil, err
	}
	return pins.OpenWith(data, sig, s.Keys)
}

func (s *Store) writeCache(b Bundle) error {
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(s.Dir, pinsFile), b.Data); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.Dir, sigFile), b.Sig)
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
