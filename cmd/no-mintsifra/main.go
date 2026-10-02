// Command no-mintsifra opens sites that present Russian Trusted CA
// certificates in any browser without installing the Russian root.
//
// Release builds are windowless so the proxy started at sign-in shows
// nothing; every other command opens a console of its own.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/Nettrove/no-mintsifra/internal/winshell"
)

// Set at build time by the release workflow.
var version = "dev"

var hasConsole bool

func main() {
	cmd, args := "menu", os.Args[1:]
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	var ownWindow bool
	if cmd != "serve" {
		hasConsole, ownWindow = winshell.OpenConsole("no-mintsifra")
	}

	err := dispatch(cmd, args)
	if err != nil {
		report(err)
	}
	// A console opened by this process vanishes with it; let the user read it first.
	if ownWindow && cmd != "menu" {
		pause()
	}
	if err != nil {
		os.Exit(1)
	}
}

func dispatch(cmd string, args []string) error {
	switch cmd {
	case "menu":
		return menu()
	case "install":
		return install(args)
	case "uninstall":
		return uninstall(args)
	case "serve":
		return serve()
	case purgeCmd:
		return purge(args)
	case "update":
		return updatePins()
	case "doctor":
		return doctor(args)
	case "sites":
		return sites()
	case "version", "--version", "-v":
		fmt.Println("no-mintsifra", version)
		return nil
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("неизвестная команда %q", cmd)
	}
}

var errCancelled = errors.New("отменено")

func report(err error) {
	if errors.Is(err, errCancelled) {
		return
	}
	if !hasConsole {
		winshell.Notify("no-mintsifra", err.Error())
		return
	}
	fmt.Fprintln(os.Stderr, red("Ошибка:"), err)
}

func usage() {
	fmt.Print(`no-mintsifra: сайты с сертификатами Минцифры в любом браузере, без сертификата Минцифры на компьютере

  no-mintsifra                меню (двойной клик)
  no-mintsifra install [-y]   включить обход
  no-mintsifra uninstall [-y] выключить и удалить из системы
  no-mintsifra doctor [--report]
                              проверить установку и каждый сайт; --report
                              сохраняет отчёт для сообщения об ошибке
  no-mintsifra remove-ministry-ca [-y]
                              найти и удалить сертификаты Минцифры из Windows
  no-mintsifra update         обновить список сайтов
  no-mintsifra sites          показать охваченные сайты
  no-mintsifra version
`)
}
