package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/Nettrove/no-mintsifra/internal/app"
	"github.com/Nettrove/no-mintsifra/internal/localca"
	"github.com/Nettrove/no-mintsifra/internal/pins"
	"github.com/Nettrove/no-mintsifra/internal/proxy"
	"github.com/Nettrove/no-mintsifra/internal/russianca"
	"github.com/Nettrove/no-mintsifra/internal/sysproxy"
)

const (
	logEvents   = 200
	logFileSize = 1 << 20
)

// serve runs the proxy until the process ends. A second copy started while
// one is already listening exits quietly.
func serve() error {
	paths, err := app.DefaultPaths()
	if err != nil {
		return err
	}
	ca, err := localca.Load(paths.CADir())
	if err != nil {
		return fmt.Errorf("сертификат no-mintsifra не найден, запустите установку заново: %w", err)
	}
	l, err := net.Listen("tcp", app.ProxyAddr)
	if err != nil {
		if proxyRunning() {
			return nil
		}
		return fmt.Errorf("не удалось занять %s: %w", app.ProxyAddr, err)
	}
	pac := func() []byte { return proxy.PAC(app.ProxyAddr, ca.Cert.PermittedDNSDomains, others()) }
	log := proxy.NewLog(paths.LogFile(), logEvents, logFileSize)
	go log.Run(context.Background(), 10*time.Second)

	// The Sub CAs and the leaf keys come from the signed list and follow it
	// as it refreshes.
	var russian atomic.Pointer[russianca.Verifier]
	var known atomic.Pointer[map[string]bool]
	useList := func(set *pins.Set) {
		russian.Store(russianca.Default.WithIntermediates(set.IntermediateCerts()))
		keys := map[string]bool{}
		for _, k := range set.SPKIs(time.Now()) {
			keys[k] = true
		}
		known.Store(&keys)
	}
	russian.Store(russianca.Default)
	known.Store(&map[string]bool{})
	if set, err := app.NewStore(paths).Current(); err == nil {
		useList(set)
	}
	verify := func(chain []*x509.Certificate, host string) error {
		return proxy.TrustedOr(russian.Load(), chain, host)
	}
	go watch(paths, ca, useList)
	pinned := func(spki string) bool { return (*known.Load())[spki] }
	return (&proxy.Server{CA: ca, PAC: pac, Log: log, Verify: verify, Pinned: pinned}).Serve(l)
}

// others routes hosts outside the list the way the user's manual proxy did
// before the PAC took over, read afresh so a VPN client switched on later
// is picked up too.
func others() proxy.Others {
	m, err := sysproxy.ReadManual()
	if err != nil {
		return proxy.Direct
	}
	return proxy.Others{HTTP: m.Directive("http"), HTTPS: m.Directive("https"), Bypass: m.Override}
}

func proxyRunning() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, app.PACURL, nil)
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
