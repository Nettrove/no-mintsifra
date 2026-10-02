package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/Nettrove/no-mintsifra/internal/winshell"
)

const reportName = "no-mintsifra-report.txt"

// saveReport runs the checks and saves them, with what a bug report needs
// around them, as plain text in Documents.
func saveReport() error {
	var buf bytes.Buffer
	fmt.Fprintln(&buf, "no-mintsifra", version)
	fmt.Fprintln(&buf, "Windows", winshell.OSVersion())
	fmt.Fprintln(&buf, "Время", time.Now().Format(time.RFC3339))
	fmt.Fprintln(&buf)
	if err := doctorTo(io.MultiWriter(os.Stdout, &buf)); err != nil {
		fmt.Fprintln(&buf, "\nИтог:", err)
	}

	dir, err := winshell.DocumentsDir()
	if err != nil {
		dir = os.TempDir()
	}
	path := filepath.Join(dir, reportName)
	if err := os.WriteFile(path, []byte(mask(buf.String(), os.Getenv("USERPROFILE"))), 0o644); err != nil {
		return err
	}
	fmt.Println()
	fmt.Println(green("Отчёт сохранён:"), path)
	fmt.Println(dim("Приложите его к сообщению об ошибке: https://github.com/Nettrove/no-mintsifra/issues/new?template=bug.yml"))
	return nil
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// mask drops colours and replaces the profile path, which carries the
// Windows user name, with %USERPROFILE%.
func mask(text, profile string) string {
	text = ansi.ReplaceAllString(text, "")
	if profile == "" {
		return text
	}
	return regexp.MustCompile(`(?i)`+regexp.QuoteMeta(profile)).ReplaceAllLiteralString(text, "%USERPROFILE%")
}
