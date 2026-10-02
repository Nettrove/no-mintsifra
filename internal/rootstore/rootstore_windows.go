//go:build windows

package rootstore

import (
	"bytes"
	"crypto/x509"
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

const encoding = windows.X509_ASN_ENCODING | windows.PKCS_7_ASN_ENCODING

// Install adds the DER certificate to the store, replacing an identical one.
func Install(der []byte) error {
	store, err := open()
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	ctx, err := windows.CertCreateCertificateContext(encoding, unsafe.SliceData(der), uint32(len(der)))
	if err != nil {
		return err
	}
	defer windows.CertFreeCertificateContext(ctx)
	return declined(windows.CertAddCertificateContextToStore(store, ctx, windows.CERT_STORE_ADD_REPLACE_EXISTING, nil))
}

// Installed reports whether exactly this certificate is in the store.
func Installed(der []byte) bool {
	found := false
	_ = each(func(raw []byte, _ *windows.CertContext) {
		found = found || bytes.Equal(raw, der)
	})
	return found
}

// Remove deletes every certificate whose subject common name is exactly
// commonName, except keep, and returns how many were removed.
func Remove(commonName string, keep []byte) (int, error) {
	var doomed []*windows.CertContext
	err := each(func(raw []byte, ctx *windows.CertContext) {
		if bytes.Equal(raw, keep) {
			return
		}
		if c, err := x509.ParseCertificate(raw); err == nil && c.Subject.CommonName == commonName {
			doomed = append(doomed, windows.CertDuplicateCertificateContext(ctx))
		}
	})
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, ctx := range doomed {
		// CertDeleteCertificateFromStore frees ctx even when it fails.
		if err := declined(windows.CertDeleteCertificateFromStore(ctx)); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func each(fn func(raw []byte, ctx *windows.CertContext)) error {
	store, err := open()
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	var ctx *windows.CertContext
	for {
		ctx, err = windows.CertEnumCertificatesInStore(store, ctx)
		if err != nil {
			return nil
		}
		fn(unsafe.Slice(ctx.EncodedCert, ctx.Length), ctx)
	}
}

func open() (windows.Handle, error) {
	root, err := windows.UTF16PtrFromString("ROOT")
	if err != nil {
		return 0, err
	}
	return windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0, windows.CERT_SYSTEM_STORE_CURRENT_USER, uintptr(unsafe.Pointer(root)))
}

func declined(err error) error {
	if errors.Is(err, windows.ERROR_CANCELLED) {
		return ErrDeclined
	}
	return err
}
