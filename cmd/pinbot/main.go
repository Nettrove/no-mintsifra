// Command pinbot builds and signs the pin set shipped with no-mintsifra.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/Nettrove/no-mintsifra/internal/discover"
	"github.com/Nettrove/no-mintsifra/internal/pins"
	"github.com/Nettrove/no-mintsifra/internal/probe"
	"github.com/Nettrove/no-mintsifra/internal/trust"
)

const (
	// pins.json stays at schema 1 for released clients; newer ones read v2.
	pinsFile    = "pins.json"
	pinsV2File  = "pins.v2.json"
	sigSuffix   = ".sig"
	keyEnv      = "PINS_SIGNING_KEY"
	scanTimeout = 40 * time.Minute
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var err error
	switch os.Args[1] {
	case "keygen":
		err = runKeygen(os.Args[2:])
	case "build":
		err = runBuild(ctx, os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "observe":
		err = runObserve(ctx, os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pinbot:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: pinbot keygen -out FILE | build -catalog FILE -out DIR [-prev DIR] [-key FILE] | verify -dir DIR | observe -catalog FILE -out FILE [-prev DIR]")
	os.Exit(2)
}

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "file to write the private key to")
	fs.Parse(args)
	if *out == "" {
		return errors.New("keygen: -out is required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(priv)
	if err := os.WriteFile(*out, []byte(encoded+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Println("public key (hex):", hex.EncodeToString(pub))
	return nil
}

func runBuild(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	catalogPath := fs.String("catalog", "catalog/sites.yaml", "site catalog")
	outDir := fs.String("out", "", "directory for pins.json and pins.json.sig")
	prevDir := fs.String("prev", "", "directory holding the previous snapshot")
	keyPath := fs.String("key", "", "private key file (default: $"+keyEnv+")")
	obsPath := fs.String("observations", "", "chains another probe saw, each verified again here")
	fs.Parse(args)
	if *outDir == "" {
		return errors.New("build: -out is required")
	}

	key, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	entries, err := loadCatalog(*catalogPath)
	if err != nil {
		return err
	}
	prev := loadPrevious(*prevDir)

	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()
	sc := scanCatalog(ctx, entries, prev, probe.Observe, passiveExpander())
	if *obsPath != "" {
		// A broken or hostile probe can only fail to contribute.
		if external, err := readObservations(*obsPath, time.Now()); err != nil {
			fmt.Fprintln(os.Stderr, "warn: ignoring observations:", err)
		} else {
			sc.add(external)
			fmt.Printf("merged observations for %d hosts\n", len(external))
		}
	}
	set, warnings := assemble(entries, prev, time.Now(), sc)
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, "warn:", w)
	}
	if len(set.Sites) == 0 {
		return errors.New("build: no pins collected, refusing to publish an empty set")
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	if err := writeSigned(*outDir, pinsV2File, set, key); err != nil {
		return err
	}
	if err := writeSigned(*outDir, pinsFile, set.V1(), key); err != nil {
		return err
	}
	fmt.Printf("wrote %d sites, %d hosts, %d keys, %d intermediates\n", len(set.Sites), len(set.Hosts()), len(set.SPKIs(time.Now())), len(set.Intermediates))
	return nil
}

func writeSigned(dir, name string, set *pins.Set, key ed25519.PrivateKey) error {
	data, err := set.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+sigSuffix), pins.Sign(data, key), 0o644)
}

// runObserve scans the catalog and writes the raw chains without signing
// anything, for a probe that holds no key and no write access.
func runObserve(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("observe", flag.ExitOnError)
	catalogPath := fs.String("catalog", "catalog/sites.yaml", "site catalog")
	out := fs.String("out", "", "file to write the observations to")
	prevDir := fs.String("prev", "", "directory holding the previous snapshot, for its hosts")
	fs.Parse(args)
	if *out == "" {
		return errors.New("observe: -out is required")
	}
	entries, err := loadCatalog(*catalogPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()
	sc := scanCatalog(ctx, entries, loadPrevious(*prevDir), probe.Observe, passiveExpander())

	tmp := *out + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := sc.export(f, time.Now()); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, *out)
}

// passiveExpander enumerates subdomains from the passive sources and DNS.
func passiveExpander() expander {
	sources := discover.DefaultSources(&http.Client{})
	return func(ctx context.Context, domain string) []string {
		return discover.Hosts(ctx, domain, sources, discover.System{})
	}
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	dir := fs.String("dir", "", "directory holding pins.json and pins.json.sig")
	fs.Parse(args)

	for _, name := range []string{pinsFile, pinsV2File} {
		set, err := readSigned(*dir, name)
		if errors.Is(err, os.ErrNotExist) && name == pinsV2File {
			continue
		}
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		fmt.Printf("ok: %s schema %d, generated %s, %d sites, %d intermediates\n", name, set.Schema, set.Generated.Format("2006-01-02"), len(set.Sites), len(set.Intermediates))
	}
	return nil
}

func readSigned(dir, name string) (*pins.Set, error) {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(filepath.Join(dir, name+sigSuffix))
	if err != nil {
		return nil, err
	}
	return pins.OpenWith(data, sig, trust.PinsKeys())
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	var raw string
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		raw = string(b)
	} else {
		raw = os.Getenv(keyEnv)
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("signing key missing: pass -key or set %s", keyEnv)
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(b) != ed25519.PrivateKeySize {
		return nil, errors.New("signing key is malformed")
	}
	return ed25519.PrivateKey(b), nil
}

func loadPrevious(dir string) *pins.Set {
	if dir == "" {
		return nil
	}
	for _, name := range []string{pinsV2File, pinsFile} {
		set, err := readSigned(dir, name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "warn: ignoring previous", name+":", err)
			continue
		}
		return set
	}
	return nil
}
