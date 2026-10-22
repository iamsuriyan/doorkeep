package h2fp

import "testing"

func TestClassifyMeasured(t *testing.T) {
	cases := map[string]string{
		"1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p":       "chrome",
		"1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s":         "firefox",
		"3:100;4:65536;2:0|1048510465|0|m,s,a,p":                  "curl",
		"2:0;4:4194304;5:1048576;6:10485760|1073741824|0|a,m,p,s": "go",
		"2:0;3:100;4:2097152;8:1;9:1|10420225|0|m,s,a,p":          "safari",
		"1:65536|1|0|m,a,s,p":                                     "other",
		"garbage":                                                 "none",
	}
	for in, want := range cases {
		if got := ClassifyText(in); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}

func TestParseNeedsHeaders(t *testing.T) {
	if _, ok := Parse([]byte(preface)); ok {
		t.Fatal("preface alone must not produce a print")
	}
	if _, ok := Parse([]byte("GET / HTTP/1.1\r\n")); ok {
		t.Fatal("HTTP/1 parsed as h2")
	}
}
