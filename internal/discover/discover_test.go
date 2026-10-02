package discover

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

type fakeResolver map[string]bool

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if f[host] {
		return []string{"192.0.2.1"}, nil
	}
	return nil, errors.New("no such host")
}

type fakeSource struct {
	names []string
	err   error
}

func (fakeSource) Name() string { return "fake" }

func (f fakeSource) Subdomains(context.Context, string) ([]string, error) { return f.names, f.err }

func TestHostsCombinesSourcesAndWordlistThenResolves(t *testing.T) {
	res := fakeResolver{"bank.ru": true, "www.bank.ru": true, "web.bank.ru": true, "secret-api.bank.ru": true, "dead.bank.ru": false}
	got := Hosts(context.Background(), "bank.ru", []Source{fakeSource{names: []string{"secret-api.bank.ru", "dead.bank.ru"}}}, res)

	want := []string{"bank.ru", "secret-api.bank.ru", "web.bank.ru", "www.bank.ru"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestHostsSurvivesFailingSource(t *testing.T) {
	res := fakeResolver{"bank.ru": true}
	got := Hosts(context.Background(), "bank.ru", []Source{fakeSource{err: errors.New("429")}}, res)
	if !slices.Equal(got, []string{"bank.ru"}) {
		t.Fatalf("got %v", got)
	}
}

func TestCleanRejectsForeignAndMalformedNames(t *testing.T) {
	cases := map[string]string{
		"*.api.bank.ru":     "api.bank.ru",
		"API.Bank.RU":       "api.bank.ru",
		"evil.example.com":  "",
		"notbank.ru":        "",
		"a b.bank.ru":       "",
		"bank.ru":           "bank.ru",
		"x.bank.ru.evil.io": "",
	}
	for in, want := range cases {
		if got := clean(in, "bank.ru"); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLimitCapsCandidates(t *testing.T) {
	set := map[string]struct{}{}
	for i := 0; i < maxCandidates+100; i++ {
		set[string(rune('a'+i%26))+string(rune('a'+i/26%26))+string(rune('a'+i/676))+".bank.ru"] = struct{}{}
	}
	if got := limit(set); len(got) != maxCandidates {
		t.Fatalf("kept %d candidates", len(got))
	}
}

func TestParsers(t *testing.T) {
	if got := parseCertspotter([]byte(`[{"dns_names":["a.bank.ru","b.bank.ru"]},{"dns_names":["c.bank.ru"]}]`)); len(got) != 3 {
		t.Errorf("certspotter: %v", got)
	}
	if got := parseCrtsh([]byte(`[{"name_value":"a.bank.ru\nb.bank.ru"}]`)); len(got) != 2 {
		t.Errorf("crt.sh: %v", got)
	}
	if got := parseHackertarget([]byte("a.bank.ru,1.2.3.4\nb.bank.ru,5.6.7.8\nAPI count exceeded")); len(got) != 2 {
		t.Errorf("hackertarget: %v", got)
	}
	if got := parseJSONStrings([]byte(`["a.bank.ru"]`)); len(got) != 1 {
		t.Errorf("anubis: %v", got)
	}
	if got := parseCertspotter([]byte(`not json`)); got != nil {
		t.Errorf("garbage must parse to nothing, got %v", got)
	}
}

func TestEndpointReportsHTTPErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	e := endpoint{name: "limited", format: srv.URL + "/%s", client: srv.Client(), parse: parseJSONStrings}
	if _, err := e.Subdomains(context.Background(), "bank.ru"); err == nil {
		t.Fatal("expected an error for http 429")
	}
}
