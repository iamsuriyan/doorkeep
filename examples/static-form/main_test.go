package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/iamsuriyan/doorkeep/pkg/verify"
)

func TestSignupVerifiesToken(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		switch {
		case r.URL.Path == "/v1/dk.js":
			w.Write([]byte("// snippet"))
		case r.URL.Path == "/v1/siteverify" && r.Form.Get("response") == "good" && r.Form.Get("expected_action") == "signup":
			w.Write([]byte(`{"success":true,"error-codes":[],"doorkeep":{"risk":3,"outcome":"allow"}}`))
		default:
			w.Write([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
		}
	}))
	defer fake.Close()
	h, err := newHandler(fake.URL, "dk_pk_test", verify.New(fake.URL, "dk_sk_test"))
	if err != nil {
		t.Fatal(err)
	}
	site := httptest.NewServer(h)
	defer site.Close()

	res, _ := http.Get(site.URL + "/")
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), `data-sitekey="dk_pk_test"`) {
		t.Fatal("site key not in page")
	}
	res, _ = http.Get(site.URL + "/_dk/v1/dk.js")
	if b, _ := io.ReadAll(res.Body); string(b) != "// snippet" {
		t.Fatalf("proxy: %q", b)
	}
	for tok, want := range map[string]int{"good": 200, "forged": 403, "": 403} {
		res, _ := http.PostForm(site.URL+"/signup", url.Values{"email": {"a@example.com"}, "dk-response": {tok}})
		if res.StatusCode != want {
			t.Errorf("token %q: %d, want %d", tok, res.StatusCode, want)
		}
	}
}
