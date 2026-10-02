//go:build !windows

package rootstore

import "crypto/x509"

func Find(func(*x509.Certificate) bool) []Found { return nil }

func Delete(Found) error { return ErrUnsupported }

func Add(Found) error { return ErrUnsupported }
