package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Nettrove/no-mintsifra/internal/app"
	"github.com/Nettrove/no-mintsifra/internal/autostart"
	"github.com/Nettrove/no-mintsifra/internal/localca"
	"github.com/Nettrove/no-mintsifra/internal/pins"
	"github.com/Nettrove/no-mintsifra/internal/rootstore"
	"github.com/Nettrove/no-mintsifra/internal/sysproxy"
)

const staleAfter = 7 * 24 * time.Hour

func updatePins() error {
	paths, err := app.DefaultPaths()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	set, changed, err := app.NewStore(paths).Refresh(ctx)
	if set == nil {
		return err
	}
	switch {
	case changed:
		fmt.Println(green("Список сайтов обновлён:"), set.Generated.Local().Format("02.01.2006 15:04"))
	case err == nil:
		fmt.Println("Уже актуально:", set.Generated.Local().Format("02.01.2006 15:04"))
	default:
		fmt.Println(yellow("Обновить не удалось, работаем с имеющимся списком от"), set.Generated.Local().Format("02.01.2006"))
		fmt.Println(dim(err.Error()))
	}
	if ca, err := localca.Load(paths.CADir()); err == nil {
		if added, removed := coverageDiff(ca.Cert.PermittedDNSDomains, set.Coverage()); len(added)+len(removed) > 0 {
			fmt.Println(yellow(fmt.Sprintf("Охват изменился: добавится %d, уберётся %d. Чтобы применить, включите обход заново (пункт 1).", len(added), len(removed))))
		}
	}
	return nil
}

func sites() error {
	paths, err := app.DefaultPaths()
	if err != nil {
		return err
	}
	set, err := app.NewStore(paths).Current()
	if err != nil {
		return err
	}
	for _, s := range set.Sites {
		fmt.Println(cyan(s.Name))
		for _, h := range s.Hosts {
			fmt.Println("   ", h)
		}
	}
	fmt.Println()
	fmt.Println(cyan("Охват сертификата no-mintsifra"), dim("(каждое имя вместе с поддоменами)"))
	for _, d := range set.Coverage() {
		fmt.Println("   ", d)
	}
	return nil
}

func doctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	report := fs.Bool("report", false, "сохранить отчёт для сообщения об ошибке")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *report {
		return saveReport()
	}
	return doctorTo(os.Stdout)
}

// doctorTo checks the installation and every covered name, writing as it goes.
func doctorTo(w io.Writer) error {
	paths, err := app.DefaultPaths()
	if err != nil {
		return err
	}
	set, err := app.NewStore(paths).Current()
	if err != nil {
		return err
	}

	ca, caErr := localca.Load(paths.CADir())
	pac, _ := sysproxy.Current()
	running := proxyRunning()
	failed := 0
	check := func(ok bool, text string) {
		mark := green("✓")
		if !ok {
			mark, failed = red("✗"), failed+1
		}
		fmt.Fprintln(w, "  ", mark, text)
	}

	fmt.Fprintln(w, "Установка:")
	check(caErr == nil && rootstore.Installed(ca.Cert.Raw), "сертификат «"+localca.CommonName+"» доверен Windows")
	check(running, "прокси работает на "+app.ProxyAddr)
	check(pac == app.PACURL, "Windows направляет сайты из списка в прокси")
	check(autostart.Command(app.Name) != "", "автозапуск при входе в Windows")
	fmt.Fprintln(w, "   ", dim("→"), "остальной трафик:", otherTraffic())
	if tag := newerRelease(paths); tag != "" {
		fmt.Fprintln(w, "   ", dim("→"), releaseLine(tag))
	}

	age := time.Since(set.Generated)
	freshness := fmt.Sprintf("список от %s", set.Generated.Local().Format("02.01.2006"))
	if age > staleAfter {
		freshness = yellow(freshness + ", устарел: выполните no-mintsifra update")
	}
	fmt.Fprintf(w, "\nСайты (%s):\n", freshness)
	if caErr != nil || !running {
		fmt.Fprintln(w, "  ", dim("пропущено: сначала выполните no-mintsifra install"))
		recentErrors(w, paths)
		return errors.New("no-mintsifra не установлен или не запущен")
	}

	var mu sync.Mutex
	checkSites(proxyClient(ca), ca.Covers, set.Coverage(), func(v verdict) {
		mu.Lock()
		defer mu.Unlock()
		mark := green("✓")
		if !v.ok {
			mark, failed = red("✗"), failed+1
		}
		fmt.Fprintf(w, "  %s %-28s %s\n", mark, v.host, v.text)
	})
	heldBack(w, set)
	recentErrors(w, paths)
	if failed > 0 {
		return errors.New("часть проверок не прошла")
	}
	return nil
}

// heldBack lists the hosts left out of the coverage by design, so that a
// site which moved to a Ministry certificate there is not a mystery.
func heldBack(w io.Writer, set *pins.Set) {
	hosts := set.HeldBack()
	if len(hosts) == 0 {
		return
	}
	fmt.Fprintln(w, "\nНе покрыты по политике безопасности:")
	for _, h := range hosts {
		fmt.Fprintln(w, "   •", h)
	}
	fmt.Fprintln(w, "   ", dim("Сертификат на эти имена охватил бы и все их поддомены, где работают другие сервисы,"))
	fmt.Fprintln(w, "   ", dim("или это сервисы, которые программа не трогает никогда. С сертификатом Минцифры они не откроются."))
}

// recentErrors prints the last failures the proxy logged.
func recentErrors(w io.Writer, paths app.Paths) {
	lines := lastLines(paths.LogFile(), 15)
	if len(lines) == 0 {
		return
	}
	fmt.Fprintln(w, "\nПоследние ошибки прокси:")
	for _, l := range lines {
		fmt.Fprintln(w, "  ", dim(l))
	}
}

// lastLines returns up to n last lines of path, reaching into the rotated
// copy when the current file is short.
func lastLines(path string, n int) []string {
	var lines []string
	for _, p := range []string{path + ".1", path} {
		if raw, err := os.ReadFile(p); err == nil {
			lines = append(lines, strings.Split(strings.TrimSpace(string(raw)), "\n")...)
		}
	}
	lines = slices.DeleteFunc(lines, func(l string) bool { return l == "" })
	return lines[max(0, len(lines)-n):]
}

// otherTraffic says where the PAC sends hosts outside the list.
func otherTraffic() string {
	o := others()
	if o.HTTPS == "DIRECT" && o.HTTP == "DIRECT" {
		return "напрямую"
	}
	m, _ := sysproxy.ReadManual()
	return "через прокси " + m.Server + dim(" (как настроено в Windows, например VPN-клиентом)")
}

type verdict struct {
	host, text string
	ok         bool
}

// checkSites opens every domain with client and reports each result as soon
// as it is known.
func checkSites(client *http.Client, covers func(string) bool, domains []string, report func(verdict)) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, domain := range domains {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			report(judge(client, covers, domain))
		}()
	}
	wg.Wait()
}

// proxyClient goes through the running proxy and trusts only the local CA,
// which is exactly the path a browser takes.
func proxyClient(ca *localca.CA) *http.Client {
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	proxyURL, _ := url.Parse("http://" + app.ProxyAddr)
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig:   &tls.Config{RootCAs: roots},
			ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// judge opens the domain, or its www host when the bare name does not answer.
func judge(client *http.Client, covers func(string) bool, domain string) verdict {
	if !covers(domain) {
		return verdict{host: domain, text: "не покрыт: включите обход заново (пункт 1)"}
	}
	var last error
	for _, host := range []string{domain, "www." + domain} {
		req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/", nil)
		// Bot filters drop Go's default agent outright but answer a named one.
		req.Header.Set("User-Agent", "no-mintsifra-doctor/"+version)
		resp, err := client.Do(req)
		if err != nil {
			last = err
			continue
		}
		resp.Body.Close()
		return verdict{host: host, ok: true, text: fmt.Sprintf("открывается (%s)", resp.Status)}
	}
	return verdict{host: domain, text: "не открылся: " + shortErr(last)}
}

func shortErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	s := err.Error()
	if len(s) > 70 {
		s = s[:70] + "…"
	}
	return s
}
