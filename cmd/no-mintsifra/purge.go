package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/Nettrove/no-mintsifra/internal/rootstore"
	"github.com/Nettrove/no-mintsifra/internal/russianca"
	"github.com/Nettrove/no-mintsifra/internal/winshell"
)

const purgeCmd = "remove-ministry-ca"

// ministryCAs finds the Ministry's own certificates.
func ministryCAs() []rootstore.Found {
	return rootstore.Find(russianca.IsMinistryCA)
}

func purge(args []string) error {
	fs := flag.NewFlagSet(purgeCmd, flag.ContinueOnError)
	yes := fs.Bool("y", false, "не спрашивать подтверждение")
	machineOnly := fs.Bool("machine", false, "только хранилища компьютера (нужны права администратора)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *machineOnly {
		return purgeFrom(ministryCAs(), rootstore.Machine)
	}
	return doPurge(*yes)
}

// doPurge removes every Ministry certificate authority it finds, asking for
// administrator rights only when one sits in the computer-wide stores.
func doPurge(assumeYes bool) error {
	found := ministryCAs()
	if len(found) == 0 {
		fmt.Println(green("Сертификатов Минцифры в Windows нет."), "Всё чисто.")
		return nil
	}
	fmt.Println("Найдены сертификаты Минцифры. Пока они стоят, Минцифры может выдать «настоящий» сертификат для любого сайта:")
	machine := false
	for _, f := range found {
		where := "у вашей учётной записи"
		if f.Location == rootstore.Machine {
			where, machine = "у всего компьютера", true
		}
		fmt.Printf("  • %s %s\n", f.Cert.Subject.CommonName, dim("("+where+")"))
	}
	fmt.Println()
	fmt.Println(dim("Сайты из списка продолжат открываться в браузерах, если обход включён (пункт 1)."))
	fmt.Println()
	fmt.Println(yellow("Важно: программы вне браузера (1С, банк-клиенты, корпоративный софт) не используют no-mintsifra"))
	fmt.Println(yellow("и после удаления могут перестать подключаться к этим сайтам."))
	fmt.Println(dim("Вернуть их можно, скачав заново с gosuslugi.ru/crt."))
	if !assumeYes && !confirm("Удалить их?") {
		return errCancelled
	}

	if err := purgeFrom(found, rootstore.User); err != nil {
		return err
	}
	if machine {
		fmt.Println(cyan("Для сертификатов всего компьютера Windows спросит права администратора. Нажмите «Да»."))
		self, err := os.Executable()
		if err != nil {
			return err
		}
		if err := winshell.RunElevated(self, purgeCmd, "-machine"); err != nil {
			return fmt.Errorf("без прав администратора сертификаты компьютера остались: %w", err)
		}
	}

	if left := ministryCAs(); len(left) > 0 {
		return fmt.Errorf("удалены не все: осталось %d", len(left))
	}
	fmt.Println(green("Готово: сертификатов Минцифры в Windows больше нет."))
	return nil
}

func purgeFrom(found []rootstore.Found, loc rootstore.Location) error {
	var errs []error
	for _, f := range found {
		if f.Location != loc {
			continue
		}
		if err := rootstore.Delete(f); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f.Cert.Subject.CommonName, err))
			continue
		}
		fmt.Println("  ", green("✓"), "удалён", f.Cert.Subject.CommonName)
	}
	return errors.Join(errs...)
}
