package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func paint(code, s string) string { return "\x1b[" + code + "m" + s + "\x1b[0m" }

func green(s string) string  { return paint("32", s) }
func red(s string) string    { return paint("31", s) }
func yellow(s string) string { return paint("33", s) }
func cyan(s string) string   { return paint("36;1", s) }
func dim(s string) string    { return paint("90", s) }

func banner() {
	fmt.Println()
	fmt.Println(cyan("  no-mintsifra"), dim(version))
	fmt.Println(dim("  Сайты на сертификатах Минцифры в любом браузере. Сам сертификат Минцифры не ставится."))
	fmt.Println()
}

func clearScreen() { fmt.Print("\x1b[2J\x1b[3J\x1b[H") }

// ask prints prompt and returns the trimmed line the user typed.
func ask(prompt string) string {
	fmt.Print(prompt, ": ")
	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(answer)
}

// confirm asks a yes/no question; Enter means yes.
func confirm(question string) bool {
	fmt.Printf("%s [%s/n] ", question, green("Y"))
	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "", "y", "yes", "д", "да":
		return true
	}
	return false
}

func pause() {
	fmt.Print(dim("\nНажмите Enter, чтобы продолжить…"))
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}
