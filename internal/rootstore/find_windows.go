//go:build windows

package rootstore

import (
	"bytes"
	"crypto/x509"
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Find lists certificates that match in the trusted root and intermediate
// stores of the current user and of the machine. Registry stores are read
// directly, so a machine certificate is not reported again as the user's.
func Find(match func(*x509.Certificate) bool) []Found {
	var out []Found
	for _, loc := range []Location{User, Machine} {
		for _, name := range []string{"Root", "CA"} {
			store, err := openRegistry(loc, name, true)
			if err != nil {
				continue
			}
			var ctx *windows.CertContext
			for {
				if ctx, err = windows.CertEnumCertificatesInStore(store, ctx); err != nil {
					break
				}
				c, err := x509.ParseCertificate(bytes.Clone(unsafe.Slice(ctx.EncodedCert, ctx.Length)))
				if err == nil && match(c) {
					out = append(out, Found{Cert: c, Location: loc, Store: name})
				}
			}
			windows.CertCloseStore(store, 0)
		}
	}
	return out
}

// Delete removes f from its store. Deleting from the user's Root store makes
// Windows ask for confirmation; machine stores need an elevated process.
func Delete(f Found) error {
	store, err := openRegistry(f.Location, f.Store, false)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	var ctx *windows.CertContext
	for {
		if ctx, err = windows.CertEnumCertificatesInStore(store, ctx); err != nil {
			return errors.New("rootstore: certificate is no longer in the store")
		}
		if bytes.Equal(unsafe.Slice(ctx.EncodedCert, ctx.Length), f.Cert.Raw) {
			return declined(windows.CertDeleteCertificateFromStore(windows.CertDuplicateCertificateContext(ctx)))
		}
	}
}

// Add puts f.Cert into the store f names. Adding to the user's Root store
// makes Windows ask for confirmation; machine stores need an elevated process.
func Add(f Found) error {
	p, err := windows.UTF16PtrFromString(f.Store)
	if err != nil {
		return err
	}
	flags := uint32(windows.CERT_SYSTEM_STORE_CURRENT_USER)
	if f.Location == Machine {
		flags = windows.CERT_SYSTEM_STORE_LOCAL_MACHINE
	}
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0, flags, uintptr(unsafe.Pointer(p)))
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	ctx, err := windows.CertCreateCertificateContext(encoding, unsafe.SliceData(f.Cert.Raw), uint32(len(f.Cert.Raw)))
	if err != nil {
		return err
	}
	defer windows.CertFreeCertificateContext(ctx)
	return declined(windows.CertAddCertificateContextToStore(store, ctx, windows.CERT_STORE_ADD_USE_EXISTING, nil))
}

func openRegistry(loc Location, name string, readOnly bool) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.CERT_SYSTEM_STORE_CURRENT_USER)
	if loc == Machine {
		flags = windows.CERT_SYSTEM_STORE_LOCAL_MACHINE
	}
	flags |= windows.CERT_STORE_OPEN_EXISTING_FLAG
	if readOnly {
		flags |= windows.CERT_STORE_READONLY_FLAG
	}
	return windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM_REGISTRY, 0, 0, flags, uintptr(unsafe.Pointer(p)))
}
