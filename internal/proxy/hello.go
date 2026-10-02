package proxy

import (
	"slices"

	utls "github.com/refraction-networking/utls"
)

// extRecordSizeLimit is sent by Firefox and not by Chromium.
const extRecordSizeLimit = 0x001c

// fallbackHello picks the stock hello closest to the browser's when its own
// cannot be mirrored, so the fingerprint does not contradict its User-Agent.
func fallbackHello(record []byte) utls.ClientHelloID {
	if hasExtension(record, extRecordSizeLimit) {
		return utls.HelloFirefox_Auto
	}
	return utls.HelloChrome_Auto
}

// fallbackSpec is the stock hello for record with its ALPN narrowed to the
// protocols the client offered. A stock hello offers h2, and a server that
// takes it cannot talk to a client that speaks only HTTP/1.1.
func fallbackSpec(record []byte, offered []string) (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(fallbackHello(record))
	if err != nil {
		return nil, err
	}
	narrow := func(protos []string) []string {
		return slices.DeleteFunc(slices.Clone(protos), func(p string) bool { return !slices.Contains(offered, p) })
	}
	exts := spec.Extensions[:0]
	for _, e := range spec.Extensions {
		switch e := e.(type) {
		case *utls.ALPNExtension:
			if e.AlpnProtocols = narrow(e.AlpnProtocols); len(e.AlpnProtocols) == 0 {
				continue
			}
		case *utls.ApplicationSettingsExtension:
			if e.SupportedProtocols = narrow(e.SupportedProtocols); len(e.SupportedProtocols) == 0 {
				continue
			}
		case *utls.ApplicationSettingsExtensionNew:
			if e.SupportedProtocols = narrow(e.SupportedProtocols); len(e.SupportedProtocols) == 0 {
				continue
			}
		}
		exts = append(exts, e)
	}
	spec.Extensions = exts
	return &spec, nil
}

// hasExtension reports whether the ClientHello in a TLS record carries the
// extension id. A malformed hello has none.
func hasExtension(record []byte, id uint16) bool {
	const fixed = 5 + 4 + 2 + 32 // record and handshake headers, version, random
	if len(record) < fixed {
		return false
	}
	p := record[fixed:]
	skip := func(n int) bool {
		if n > len(p) {
			return false
		}
		p = p[n:]
		return true
	}
	vector := func(lenBytes int) bool {
		if len(p) < lenBytes {
			return false
		}
		n := int(p[0])
		if lenBytes == 2 {
			n = n<<8 | int(p[1])
		}
		return skip(lenBytes + n)
	}
	// session id, cipher suites, compression methods, extensions length
	if !vector(1) || !vector(2) || !vector(1) || !skip(2) {
		return false
	}
	for len(p) >= 4 {
		if uint16(p[0])<<8|uint16(p[1]) == id {
			return true
		}
		if !skip(4 + (int(p[2])<<8 | int(p[3]))) {
			return false
		}
	}
	return false
}
