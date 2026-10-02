// Package trust holds the keys that sign the published pin sets.
package trust

import (
	"crypto/ed25519"
	"encoding/hex"
	"time"

	"github.com/Nettrove/no-mintsifra/internal/pins"
)

// pinsKeys lists every list signing key, the current one first. When a key
// is retired, its notAfter is set to the moment it stopped being trusted,
// for example the suspected time of a leak; lists it signed later are
// refused by this and every newer version.
var pinsKeys = []struct {
	hex      string
	notAfter string // RFC 3339, empty while the key is current
}{
	{hex: "e5e472d7139c69c79954e34e036647585b44928c5af3fde8ebf793aa474347a1"},
}

// PinsKeys returns the list signing keys with their validity windows.
func PinsKeys() []pins.Key {
	out := make([]pins.Key, 0, len(pinsKeys))
	for _, k := range pinsKeys {
		pub, err := hex.DecodeString(k.hex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			panic("trust: embedded public key is invalid")
		}
		key := pins.Key{Public: pub}
		if k.notAfter != "" {
			if key.NotAfter, err = time.Parse(time.RFC3339, k.notAfter); err != nil {
				panic("trust: embedded key window is invalid")
			}
		}
		out = append(out, key)
	}
	return out
}
