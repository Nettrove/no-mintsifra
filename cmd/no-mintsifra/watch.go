package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/Nettrove/no-mintsifra/internal/app"
	"github.com/Nettrove/no-mintsifra/internal/localca"
	"github.com/Nettrove/no-mintsifra/internal/pins"
	"github.com/Nettrove/no-mintsifra/internal/winshell"
)

const (
	refreshEvery = 12 * time.Hour
	// The first refresh waits for the network to come up after sign-in.
	firstRefresh = 5 * time.Minute
)

// watch keeps the site list fresh while the proxy runs, hands each refreshed
// list to useList and tells the user once when the CA no longer matches it.
// The CA itself changes only from the menu, with the user's consent. The
// jitter keeps every installation from hitting the mirrors at the same minute.
// Notices are shown from their own goroutine: a message box waits for a click,
// and one lost behind other windows must not stop the refresh.
func watch(paths app.Paths, ca *localca.CA, useList func(*pins.Set)) {
	store := app.NewStore(paths)
	wait := firstRefresh + jitter(10*time.Minute)
	for {
		time.Sleep(wait)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		set, _, _ := store.Refresh(ctx)
		cancel()
		if set != nil {
			useList(set)
			st := loadState(paths)
			if msg, key := coverageNotice(ca.Cert.PermittedDNSDomains, set.Coverage(), st.CoverageNotice); msg != "" {
				st.CoverageNotice = key
				_ = saveState(paths, st)
				go winshell.Notify(app.Name, msg)
			}
		}
		st := loadState(paths)
		if msg, key := expiryNotice(ca.Cert, time.Now(), st.ExpiryNotice); msg != "" {
			st.ExpiryNotice = key
			_ = saveState(paths, st)
			go winshell.Notify(app.Name, msg)
		}
		wait = refreshEvery + jitter(time.Hour)
	}
}

// coverageNotice returns the message to show when the list asks for a
// different coverage than the CA has, unless that coverage was already
// announced, and the key to remember it by.
func coverageNotice(have, want []string, shown string) (msg, key string) {
	added, removed := coverageDiff(have, want)
	key = strings.Join(want, ",")
	if len(added)+len(removed) == 0 || key == shown {
		return "", key
	}
	what := fmt.Sprintf("новых доменов: %d, убранных: %d", len(added), len(removed))
	return "Список сайтов изменился (" + what + ").\n\nЧтобы применить его, откройте no-mintsifra из меню «Пуск» и выберите пункт 1.", key
}

// expiryNotice warns once per CA when it is close enough to expiry for
// menu item 1 to replace it.
func expiryNotice(ca *x509.Certificate, now time.Time, shown string) (msg, key string) {
	key = ca.SerialNumber.Text(16)
	if ca.NotAfter.Sub(now) > caRenewAhead || key == shown {
		return "", key
	}
	return "Сертификат no-mintsifra действует до " + ca.NotAfter.Local().Format("02.01.2006") +
		".\n\nЧтобы продлить его, откройте no-mintsifra из меню «Пуск» и выберите пункт 1.", key
}

func jitter(limit time.Duration) time.Duration { return rand.N(limit) }
