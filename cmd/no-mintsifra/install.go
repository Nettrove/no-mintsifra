package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Nettrove/no-mintsifra/internal/app"
	"github.com/Nettrove/no-mintsifra/internal/appentry"
	"github.com/Nettrove/no-mintsifra/internal/autostart"
	"github.com/Nettrove/no-mintsifra/internal/localca"
	"github.com/Nettrove/no-mintsifra/internal/pins"
	"github.com/Nettrove/no-mintsifra/internal/rootstore"
	"github.com/Nettrove/no-mintsifra/internal/sysproxy"
	"github.com/Nettrove/no-mintsifra/internal/winshell"
)

const (
	manifestName = "installed.json"
	caRenewAhead = 60 * 24 * time.Hour
)

type manifest struct {
	// Shortcuts we created, including browser ones from versions before the proxy.
	Shortcuts []string `json:"shortcuts,omitempty"`
	Dirs      []string `json:"dirs,omitempty"`
	// The user's own PAC setting, put back on uninstall.
	PreviousProxy *sysproxy.State `json:"previousProxy,omitempty"`
}

func install(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	yes := fs.Bool("y", false, "не спрашивать подтверждение")
	if err := fs.Parse(args); err != nil {
		return err
	}
	banner()
	return doInstall(*yes)
}

func doInstall(assumeYes bool) error {
	paths, err := app.DefaultPaths()
	if err != nil {
		return err
	}
	set, err := freshPins(paths)
	if err != nil {
		return err
	}
	domains := set.Coverage()

	fmt.Println("Что будет сделано:")
	fmt.Println("  •", "программа скопируется в", dim(paths.Root))
	fmt.Printf("  • появится сертификат «%s»: только для этого компьютера и только для %d доменов на сертификатах Минцифры\n", localca.CommonName, len(domains))
	fmt.Println("  •", green("сертификат Минцифры не устанавливается"), "ни в Windows, ни в браузеры")
	fmt.Println("  •", "эти сайты пойдут через no-mintsifra на этом же компьютере, остальной интернет напрямую, как раньше")
	fmt.Println("  •", "обход будет включаться сам при входе в Windows")
	if current, _ := sysproxy.Current(); current != "" && current != app.PACURL {
		fmt.Println()
		fmt.Println(yellow("  В Windows уже задан прокси-скрипт: " + current))
		fmt.Println(yellow("  Пока no-mintsifra установлен, он будет заменён; при удалении вернётся обратно."))
	}
	if m, err := sysproxy.ReadManual(); err == nil && m.Directive("https") != "DIRECT" {
		fmt.Println()
		fmt.Println(yellow("  В Windows включён прокси " + m.Server + ", обычно его ставит VPN-клиент."))
		fmt.Println(yellow("  Сайты из списка пойдут через no-mintsifra напрямую, весь остальной трафик по-прежнему через этот прокси."))
	}
	// Trust is never widened silently: new names are shown and need a yes.
	widens := false
	if old, err := localca.Load(paths.CADir()); err == nil {
		added, removed := coverageDiff(old.Cert.PermittedDNSDomains, domains)
		if len(added)+len(removed) > 0 {
			fmt.Println()
			fmt.Println("  Список доменов сертификата изменится:")
			printNames(green("добавятся:"), added)
			printNames(yellow("уберутся:"), removed)
			widens = len(added) > 0
		}
	}
	fmt.Println()
	if (!assumeYes || widens) && !confirm("Продолжить?") {
		return errCancelled
	}

	if err := os.MkdirAll(paths.Root, 0o755); err != nil {
		return err
	}
	stopProxies(paths)
	runTarget, err := copyBinaries(paths)
	if err != nil {
		return err
	}
	ca, err := ensureCA(paths, domains)
	if err != nil {
		return err
	}
	if err := trustCA(ca); err != nil {
		return err
	}

	m := readManifest(paths)
	prev, err := sysproxy.Set(app.PACURL)
	if err != nil {
		return fmt.Errorf("не удалось настроить прокси Windows: %w", err)
	}
	if m.PreviousProxy == nil {
		if prev.AutoConfigURL == app.PACURL {
			prev = sysproxy.State{}
		}
		m.PreviousProxy = &prev
	}
	if err := autostart.Enable(app.Name, `"`+runTarget+`" serve`); err != nil {
		return fmt.Errorf("не удалось включить автозапуск: %w", err)
	}
	if err := winshell.StartDetached(runTarget, "serve"); err != nil {
		return err
	}
	removeOldShortcuts(&m)
	if lnk, err := addToStartMenu(runTarget); err == nil {
		m.Shortcuts = append(m.Shortcuts, lnk)
	}
	_ = appentry.Register(app.Name, appentry.Entry{
		Name:            app.Name,
		Version:         version,
		Publisher:       "Nettrove",
		Icon:            runTarget,
		InstallLocation: paths.Root,
		UninstallString: `"` + runTarget + `" uninstall`,
	})
	if err := writeManifest(paths, m); err != nil {
		return err
	}
	if !waitProxy(5 * time.Second) {
		return errors.New("прокси не запустился, выполните: no-mintsifra doctor")
	}

	fmt.Println()
	fmt.Println(green("Готово: обход включён."), "Открывайте сайты в любом браузере как обычно.")
	fmt.Println(dim("Если браузер уже открыт и сайт не грузится, перезапустите браузер один раз."))
	return nil
}

func freshPins(paths app.Paths) (*pins.Set, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store := app.NewStore(paths)
	if set, _, _ := store.Refresh(ctx); set != nil {
		return set, nil
	}
	return store.Current()
}

// ensureCA reuses the saved CA while it covers exactly these domains and is
// not about to expire, and creates a new one otherwise: a CA that covers
// more than the list asks for is replaced too.
func ensureCA(paths app.Paths, domains []string) (*localca.CA, error) {
	if ca, err := localca.Load(paths.CADir()); err == nil && slices.Equal(ca.Cert.PermittedDNSDomains, domains) && time.Until(ca.Cert.NotAfter) > caRenewAhead {
		return ca, nil
	}
	ca, err := localca.New(domains, time.Now())
	if err != nil {
		return nil, err
	}
	return ca, ca.Save(paths.CADir())
}

func printNames(label string, names []string) {
	const shown = 20
	if len(names) == 0 {
		return
	}
	list := strings.Join(names[:min(len(names), shown)], ", ")
	if len(names) > shown {
		list += fmt.Sprintf(" и ещё %d", len(names)-shown)
	}
	fmt.Println("   ", label, list)
}

// coverageDiff lists the names a CA for want adds to and drops from have.
func coverageDiff(have, want []string) (added, removed []string) {
	for _, d := range want {
		if !slices.Contains(have, d) {
			added = append(added, d)
		}
	}
	for _, d := range have {
		if !slices.Contains(want, d) {
			removed = append(removed, d)
		}
	}
	return added, removed
}

func trustCA(ca *localca.CA) error {
	if !rootstore.Installed(ca.Cert.Raw) {
		fmt.Println()
		fmt.Println(cyan("Windows сейчас спросит, доверять ли сертификату «" + localca.CommonName + "». Нажмите «Да»."))
		err := rootstore.Install(ca.Cert.Raw)
		if errors.Is(err, rootstore.ErrDeclined) {
			return errors.New("без этого сертификата сайты не откроются; установка остановлена")
		}
		if err != nil {
			return fmt.Errorf("не удалось добавить сертификат: %w", err)
		}
	}
	if n, _ := rootstore.Remove(localca.CommonName, ca.Cert.Raw); n > 0 {
		fmt.Println(dim(fmt.Sprintf("Старых сертификатов no-mintsifra удалено: %d", n)))
	}
	return nil
}

func waitProxy(limit time.Duration) bool {
	for deadline := time.Now().Add(limit); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if proxyRunning() {
			return true
		}
	}
	return false
}

// stopProxies ends running proxies so their executables can be replaced or removed.
func stopProxies(paths app.Paths) {
	for _, exe := range []string{paths.Bin(app.Exe), paths.Bin(app.LegacyRunExe)} {
		procs, _ := winshell.Processes(exe)
		var pids []int
		for _, p := range procs {
			if strings.HasSuffix(strings.TrimSpace(p.CommandLine), " serve") {
				pids = append(pids, p.PID)
			}
		}
		winshell.Kill(pids)
	}
}

// copyBinaries places the executable under the install root, drops the
// second executable older versions shipped and returns the path autostart runs.
func copyBinaries(paths app.Paths) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	target := paths.Bin(app.Exe)
	if err := copyFile(self, target); err != nil {
		return "", err
	}
	_ = os.Remove(paths.Bin(app.LegacyRunExe))
	return target, nil
}

func copyFile(src, dst string) error {
	if sameFile(src, dst) {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("не удалось записать %s (закройте запущенный no-mintsifra): %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func sameFile(a, b string) bool {
	ai, errA := os.Stat(a)
	bi, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(ai, bi)
}

func readManifest(paths app.Paths) manifest {
	var m manifest
	if raw, err := os.ReadFile(filepath.Join(paths.Root, manifestName)); err == nil {
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

func writeManifest(paths app.Paths, m manifest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(paths.Root, manifestName), raw, 0o644)
}

// addToStartMenu puts the menu one search away, so switching the bypass off
// never depends on finding the downloaded file again.
func addToStartMenu(exe string) (string, error) {
	dir, err := winshell.StartMenuDir()
	if err != nil {
		return "", err
	}
	lnk := filepath.Join(dir, app.Name+".lnk")
	return lnk, winshell.CreateShortcut(winshell.Shortcut{
		Path:        lnk,
		Target:      exe,
		Icon:        exe,
		Description: "Включить, выключить или проверить обход сертификатов Минцифры",
	})
}

func removeOldShortcuts(m *manifest) {
	for _, s := range m.Shortcuts {
		_ = os.Remove(s)
	}
	for _, d := range m.Dirs {
		_ = os.Remove(d)
	}
	m.Shortcuts, m.Dirs = nil, nil
}

func uninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	yes := fs.Bool("y", false, "не спрашивать подтверждение")
	if err := fs.Parse(args); err != nil {
		return err
	}
	banner()
	if !*yes && !confirm("Выключить обход и удалить no-mintsifra из системы?") {
		return errCancelled
	}
	return doUninstall()
}

// doUninstall undoes everything doInstall changed and deletes the install root.
func doUninstall() error {
	paths, err := app.DefaultPaths()
	if err != nil {
		return err
	}
	m := readManifest(paths)
	removeProxyMode(paths, m)
	removeOldShortcuts(&m)
	_ = appentry.Unregister(app.Name)

	if err := removeRoot(paths.Root); err != nil {
		return err
	}
	fmt.Println(green("Готово: обход выключен, из системы всё удалено."))
	return nil
}

// removeProxyMode stops the proxy and takes back what the proxy mode set up:
// autostart, the PAC URL and the local CA in the Root store.
func removeProxyMode(paths app.Paths, m manifest) {
	stopProxies(paths)
	if err := autostart.Disable(app.Name); err != nil {
		fmt.Println(yellow("Автозапуск не удалён:"), err)
	}
	var prev sysproxy.State
	if m.PreviousProxy != nil {
		prev = *m.PreviousProxy
	}
	if err := sysproxy.Restore(app.PACURL, prev); err != nil {
		fmt.Println(yellow("Настройка прокси не восстановлена:"), err)
	}
	if ca, err := localca.Load(paths.CADir()); err == nil && rootstore.Installed(ca.Cert.Raw) {
		fmt.Println(cyan("Windows спросит, удалить ли сертификат «" + localca.CommonName + "». Нажмите «Да»."))
	}
	if _, err := rootstore.Remove(localca.CommonName, nil); err != nil {
		fmt.Println(yellow("Сертификат не удалён:"), err)
	}
}

func removeRoot(root string) error {
	self, err := os.Executable()
	if err == nil && strings.HasPrefix(strings.ToLower(self), strings.ToLower(root)+string(filepath.Separator)) {
		return winshell.RemoveLater(root)
	}
	return os.RemoveAll(root)
}
