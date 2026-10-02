// Package snapshot embeds the pin set that was current when the binary was
// built. The file keeps its old name and may hold either schema.
package snapshot

import (
	"embed"

	"github.com/Nettrove/no-mintsifra/internal/update"
)

//go:embed data/pins.json data/pins.json.sig
var files embed.FS

func Bundle() update.Bundle {
	data, _ := files.ReadFile("data/pins.json")
	sig, _ := files.ReadFile("data/pins.json.sig")
	return update.Bundle{Data: data, Sig: sig}
}
