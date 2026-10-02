package rootstore

import "crypto/x509"

// Location is whose certificate store a certificate lives in.
type Location int

const (
	User Location = iota
	// Machine stores apply to every account and need an elevated process to change.
	Machine
)

// Found is one matching certificate and the store it sits in.
type Found struct {
	Cert     *x509.Certificate
	Location Location
	Store    string
}
