package proxy

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

func helloRecord(t *testing.T, id utls.ClientHelloID) []byte {
	t.Helper()
	uc := utls.UClient(nil, &utls.Config{ServerName: "www.example.com"}, id)
	if err := uc.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	body := uc.HandshakeState.Hello.Raw
	return append([]byte{0x16, 0x03, 0x01, byte(len(body) >> 8), byte(len(body))}, body...)
}

func TestFallbackFollowsTheBrowser(t *testing.T) {
	if got := fallbackHello(helloRecord(t, utls.HelloFirefox_Auto)); got != utls.HelloFirefox_Auto {
		t.Errorf("Firefox hello falls back to %v", got)
	}
	if got := fallbackHello(helloRecord(t, utls.HelloChrome_Auto)); got != utls.HelloChrome_Auto {
		t.Errorf("Chrome hello falls back to %v", got)
	}
}

func TestHasExtensionSurvivesTruncation(t *testing.T) {
	record := helloRecord(t, utls.HelloFirefox_Auto)
	for n := range len(record) {
		hasExtension(record[:n], extRecordSizeLimit)
	}
	if hasExtension([]byte{0x16, 0x03, 0x01, 0x00, 0x01, 0xff}, extRecordSizeLimit) {
		t.Fatal("found an extension in garbage")
	}
}
