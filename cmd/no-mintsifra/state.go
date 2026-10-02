package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/Nettrove/no-mintsifra/internal/app"
)

const stateName = "state.json"

// state is what the program remembers between runs, apart from the list
// and the CA, so the same notice is not shown twice.
type state struct {
	// CoverageNotice is the coverage the user was last told about.
	CoverageNotice string `json:"coverageNotice,omitempty"`
	// ExpiryNotice is the serial of the CA whose coming expiry was announced.
	ExpiryNotice string `json:"expiryNotice,omitempty"`
	// LatestRelease is the newest release seen at ReleaseChecked.
	LatestRelease  string    `json:"latestRelease,omitempty"`
	ReleaseChecked time.Time `json:"releaseChecked"`
}

func loadState(paths app.Paths) state {
	var st state
	if raw, err := os.ReadFile(filepath.Join(paths.Root, stateName)); err == nil {
		_ = json.Unmarshal(raw, &st)
	}
	return st
}

func saveState(paths app.Paths, st state) error {
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(paths.Root, stateName), raw, 0o644)
}
