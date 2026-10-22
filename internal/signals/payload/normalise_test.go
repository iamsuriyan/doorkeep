package payload

import "testing"

func TestZeroCountsAreObservedWhenSnippetRan(t *testing.T) {
	p := &Payload{V: 1, N: "aaaaaaaaaaaaaaaaaaaaaa", Beh: Beh{Key: []float64{0, 0, 0, 0, 0, 1, 0}, Foc: []float64{1, 1, 0, 0}}}
	f, _ := Normalise(p, ServerContext{})
	if !f.Has("beh.key_count") || f.Get("beh.key_count") != 0 {
		t.Fatal("zero key count should be recorded as 0")
	}
	if f.Get("beh.ptr_samples") != 0 || f.Get("beh.click_count") != 0 {
		t.Fatal("zero pointer and click counts should be recorded as 0")
	}
	if f.Get("beh.input_no_key_frac") != 1 {
		t.Fatal("fill-without-keys fraction lost")
	}
}

func TestBehaviourAbsentWhenSnippetDidNotReport(t *testing.T) {
	p := &Payload{V: 1, N: "aaaaaaaaaaaaaaaaaaaaaa"}
	f, _ := Normalise(p, ServerContext{})
	for _, k := range []string{"beh.key_count", "beh.ptr_samples", "beh.click_count"} {
		if f.Has(k) {
			t.Fatalf("%s should be unknown when no behaviour was reported", k)
		}
	}
}

func TestUAFamilies(t *testing.T) {
	cases := map[string]string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36":                         "chrome",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0":               "edge",
		"Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0":                                                                  "firefox",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1": "safari",
		"curl/8.5.0":             "curl",
		"python-requests/2.32.3": "python",
		"Go-http-client/2.0":     "go",
	}
	for ua, want := range cases {
		if got, _ := uaFamily(ua); got != want {
			t.Errorf("%s: got %s want %s", ua, got, want)
		}
	}
}
