package pins

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrBadSignature = errors.New("pins: signature mismatch")

func Sign(data []byte, key ed25519.PrivateKey) []byte {
	sig := ed25519.Sign(key, data)
	return []byte(base64.StdEncoding.EncodeToString(sig) + "\n")
}

func Verify(data, sig []byte, key ed25519.PublicKey) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil {
		return fmt.Errorf("pins: decode signature: %w", err)
	}
	if !ed25519.Verify(key, data, raw) {
		return ErrBadSignature
	}
	return nil
}

func Open(data, sig []byte, key ed25519.PublicKey) (*Set, error) {
	if err := Verify(data, sig, key); err != nil {
		return nil, err
	}
	return Parse(data)
}

// ErrRetiredKey means a set claims to be generated after the key that
// signed it was retired.
var ErrRetiredKey = errors.New("pins: signed by a retired key")

// Key checks list signatures. A list signed by it may not claim to be
// generated after NotAfter; a zero NotAfter means the key is current.
type Key struct {
	Public   ed25519.PublicKey
	NotAfter time.Time
}

// OpenWith verifies data against each key in turn and parses it, refusing
// a set that a retired key signed after its retirement.
func OpenWith(data, sig []byte, keys []Key) (*Set, error) {
	for _, k := range keys {
		if Verify(data, sig, k.Public) != nil {
			continue
		}
		set, err := Parse(data)
		if err != nil {
			return nil, err
		}
		if !k.NotAfter.IsZero() && set.Generated.After(k.NotAfter) {
			return nil, ErrRetiredKey
		}
		return set, nil
	}
	return nil, ErrBadSignature
}
