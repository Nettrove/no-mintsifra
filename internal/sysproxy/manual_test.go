package sysproxy

import (
	"slices"
	"testing"
)

func TestDirective(t *testing.T) {
	for _, tc := range []struct {
		m            Manual
		scheme, want string
	}{
		{Manual{}, "https", "DIRECT"},
		{Manual{Enabled: true}, "https", "DIRECT"},
		{Manual{Server: "127.0.0.1:10809"}, "https", "DIRECT"},
		{Manual{Enabled: true, Server: "127.0.0.1:10809"}, "https", "PROXY 127.0.0.1:10809"},
		{Manual{Enabled: true, Server: "http=h:1;https=s:2"}, "https", "PROXY s:2"},
		{Manual{Enabled: true, Server: "http=h:1;https=s:2"}, "http", "PROXY h:1"},
		{Manual{Enabled: true, Server: "HTTP=h:1; socks=k:3"}, "https", "SOCKS5 k:3; SOCKS k:3"},
		{Manual{Enabled: true, Server: "http=h:1; socks=k:3"}, "http", "PROXY h:1"},
		{Manual{Enabled: true, Server: "ftp=f:4"}, "https", "DIRECT"},
		{Manual{Enabled: true, Server: "http://127.0.0.1:7890"}, "https", "PROXY 127.0.0.1:7890"},
		{Manual{Enabled: true, Server: "HTTP://127.0.0.1:7890/"}, "http", "PROXY 127.0.0.1:7890"},
		{Manual{Enabled: true, Server: "socks5://127.0.0.1:1080"}, "https", "SOCKS5 127.0.0.1:1080; SOCKS 127.0.0.1:1080"},
		{Manual{Enabled: true, Server: "https=http://s:2;socks=socks5://k:3"}, "https", "PROXY s:2"},
		{Manual{Enabled: true, Server: "socks=socks5://k:3"}, "http", "SOCKS5 k:3; SOCKS k:3"},
	} {
		if got := tc.m.Directive(tc.scheme); got != tc.want {
			t.Errorf("%+v %s: got %q, want %q", tc.m, tc.scheme, got, tc.want)
		}
	}
}

func TestSplitOverride(t *testing.T) {
	got := splitOverride(" *.Local; 10.*;;<local> ")
	if !slices.Equal(got, []string{"*.local", "10.*", "<local>"}) {
		t.Fatalf("got %q", got)
	}
}
