package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Nettrove/no-mintsifra/internal/app"
	"github.com/Nettrove/no-mintsifra/internal/autostart"
	"github.com/Nettrove/no-mintsifra/internal/localca"
	"github.com/Nettrove/no-mintsifra/internal/rootstore"
	"github.com/Nettrove/no-mintsifra/internal/sysproxy"
	"github.com/Nettrove/no-mintsifra/internal/winshell"
)

// menu is what a double click opens: the current state and one key per action.
func menu() error {
	for {
		clearScreen()
		banner()
		paths, err := app.DefaultPaths()
		if err != nil {
			return err
		}
		fmt.Println("  Статус:", status(paths))
		if tag := newerRelease(paths); tag != "" {
			fmt.Println("  ", releaseLine(tag))
		}
		if n := len(ministryCAs()); n > 0 {
			fmt.Println("  ", yellow(fmt.Sprintf("⚠ В Windows стоит сертификат Минцифры (%d шт.): он действует для любого сайта. Пункт 5 уберёт его.", n)))
		}
		fmt.Println()
		fmt.Println("  ", cyan("1"), " Включить обход", dim("(навсегда, переживает перезагрузку)"))
		fmt.Println("  ", cyan("2"), " Выключить и удалить из системы")
		fmt.Println("  ", cyan("3"), " Проверить, что всё работает")
		fmt.Println("  ", cyan("4"), " Обновить список сайтов")
		fmt.Println("  ", cyan("5"), " Найти и удалить сертификат Минцифры из Windows")
		fmt.Println("  ", cyan("0"), " Выход")
		fmt.Println()

		switch ask("  Выберите пункт") {
		case "1":
			fmt.Println()
			err = doInstall(true)
		case "2":
			fmt.Println()
			if err = doUninstall(); err == nil {
				pause()
				return nil
			}
		case "3":
			fmt.Println()
			err = doctorTo(os.Stdout)
		case "4":
			fmt.Println()
			err = updatePins()
		case "5":
			fmt.Println()
			err = doPurge(false)
		case "0":
			return nil
		default:
			continue
		}
		if err != nil {
			report(err)
		}
		pause()
	}
}

type part struct {
	ok      bool
	problem string
}

// status describes the installation in one line, naming whatever is missing.
// A proxy that is merely not running yet, as right after sign-in, is started.
func status(paths app.Paths) string {
	ca, err := localca.Load(paths.CADir())
	trusted := err == nil && rootstore.Installed(ca.Cert.Raw)
	pac, _ := sysproxy.Current()
	routed := pac == app.PACURL
	autorun := autostart.Command(app.Name) != ""
	running := proxyRunning()
	if trusted && routed && autorun && !running {
		if winshell.StartDetached(paths.Bin(app.Exe), "serve") == nil {
			running = waitProxy(5 * time.Second)
		}
	}

	parts := []part{
		{trusted, "сертификат не доверен Windows"},
		{routed, "Windows не направляет сайты в прокси"},
		{autorun, "нет автозапуска"},
		{running, "прокси не запущен"},
	}
	var problems []string
	for _, p := range parts {
		if !p.ok {
			problems = append(problems, p.problem)
		}
	}
	switch len(problems) {
	case 0:
		return green("● ВКЛЮЧЁН") + dim(fmt.Sprintf("  (%d доменов)", len(ca.Cert.PermittedDNSDomains)))
	case len(parts):
		return dim("○ ВЫКЛЮЧЕН")
	default:
		return yellow("◐ РАБОТАЕТ НЕ ПОЛНОСТЬЮ: "+strings.Join(problems, ", ")) + dim("  (нажмите 1, чтобы починить)")
	}
}
