// Package app holds the paths and wiring shared by every command.
package app

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/Nettrove/no-mintsifra/internal/snapshot"
	"github.com/Nettrove/no-mintsifra/internal/trust"
	"github.com/Nettrove/no-mintsifra/internal/update"
)

const (
	Name = "no-mintsifra"
	Exe  = "no-mintsifra.exe"
	// LegacyRunExe is the windowless twin that versions before 0.2 installed.
	LegacyRunExe = "no-mintsifra-run.exe"
	sourcesEnv   = "NO_MINTSIFRA_SOURCES"

	// ProxyAddr is where the proxy listens; it never binds beyond loopback.
	ProxyAddr = "127.0.0.1:47123"
	PACURL    = "http://" + ProxyAddr + "/proxy.pac"
)

type Paths struct {
	Root string
}

func DefaultPaths() (Paths, error) {
	base := os.Getenv("LocalAppData")
	if base == "" {
		dir, err := os.UserCacheDir()
		if err != nil {
			return Paths{}, err
		}
		base = dir
	}
	return Paths{Root: filepath.Join(base, Name)}, nil
}

func (p Paths) PinsDir() string { return filepath.Join(p.Root, "pins") }

func (p Paths) CADir() string { return filepath.Join(p.Root, "ca") }

// LogFile is where the proxy appends failed connections.
func (p Paths) LogFile() string { return filepath.Join(p.Root, "proxy.log") }

func (p Paths) Bin(name string) string { return filepath.Join(p.Root, name) }

func NewStore(p Paths) *update.Store {
	return &update.Store{
		Dir:      p.PinsDir(),
		Sources:  update.SourcesFromEnv(os.Getenv(sourcesEnv)),
		Keys:     trust.PinsKeys(),
		Fallback: snapshot.Bundle(),
		Client:   &http.Client{},
	}
}
