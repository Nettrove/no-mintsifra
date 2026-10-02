package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Nettrove/no-mintsifra/internal/app"
)

const (
	latestReleaseAPI = "https://api.github.com/repos/Nettrove/no-mintsifra/releases/latest"
	releasesPage     = "https://github.com/Nettrove/no-mintsifra/releases/latest"
	releaseCheck     = 24 * time.Hour
)

// newerRelease returns the latest release when it is newer than this build,
// asking GitHub at most once a day. It only reports: the program never
// replaces itself.
func newerRelease(paths app.Paths) string {
	if version == "dev" {
		return ""
	}
	st := loadState(paths)
	if time.Since(st.ReleaseChecked) > releaseCheck {
		if tag, err := latestRelease(); err == nil {
			st.LatestRelease = tag
		}
		st.ReleaseChecked = time.Now()
		_ = saveState(paths, st)
	}
	if newer(st.LatestRelease, version) {
		return st.LatestRelease
	}
	return ""
}

func latestRelease() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, latestReleaseAPI, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github: %s", resp.Status)
	}
	var body struct {
		Tag string `json:"tag_name"`
	}
	err = json.NewDecoder(resp.Body).Decode(&body)
	return body.Tag, err
}

// newer reports whether tag a is a later version than b, in semver order:
// v1.0.0-beta < v1.0.0-beta.2 < v1.0.0 < v1.0.1. Build ids such as dev-1a2b3c
// never compare.
func newer(a, b string) bool {
	va, okA := parseVersion(a)
	vb, okB := parseVersion(b)
	return okA && okB && compareVersions(va, vb) > 0
}

type semver struct {
	core [3]int
	pre  []string // dot-separated pre-release ids, nil for a release
}

func parseVersion(s string) (semver, bool) {
	var v semver
	s, pre, hasPre := strings.Cut(strings.TrimPrefix(s, "v"), "-")
	if hasPre {
		if v.pre = strings.Split(pre, "."); slices.Contains(v.pre, "") {
			return v, false
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		v.core[i] = n
	}
	return v, true
}

func compareVersions(a, b semver) int {
	if c := slices.Compare(a.core[:], b.core[:]); c != 0 {
		return c
	}
	switch {
	case a.pre == nil && b.pre == nil:
		return 0
	case a.pre == nil:
		return 1
	case b.pre == nil:
		return -1
	}
	for i := range min(len(a.pre), len(b.pre)) {
		if c := compareID(a.pre[i], b.pre[i]); c != 0 {
			return c
		}
	}
	return len(a.pre) - len(b.pre)
}

// compareID orders numeric ids numerically and below alphanumeric ones.
func compareID(a, b string) int {
	na, errA := strconv.Atoi(a)
	nb, errB := strconv.Atoi(b)
	switch {
	case errA == nil && errB == nil:
		return na - nb
	case errA == nil:
		return -1
	case errB == nil:
		return 1
	}
	return strings.Compare(a, b)
}

func releaseLine(tag string) string {
	return yellow("Вышла новая версия "+tag+": ") + releasesPage
}
