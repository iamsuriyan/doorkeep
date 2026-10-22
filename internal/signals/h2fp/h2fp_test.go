package h2fp

import (
	"bytes"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

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

// chromeLikePreface builds what a Chromium-like client sends: preface,
// SETTINGS, connection WINDOW_UPDATE, then HEADERS with m,a,s,p order.
func chromeLikePreface(t testing.TB, priority int) []byte {
	var buf bytes.Buffer
	buf.WriteString(preface)
	fr := http2.NewFramer(&buf, nil)
	fr.WriteSettings(
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536},
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 6291456},
		http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 262144},
	)
	fr.WriteWindowUpdate(0, 15663105)
	for i := 0; i < priority; i++ {
		fr.WritePriority(uint32(3+2*i), http2.PriorityParam{Weight: 100})
	}
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, h := range [][2]string{{":method", "GET"}, {":authority", "shop.example"}, {":scheme", "https"}, {":path", "/"}, {"user-agent", "x"}} {
		enc.WriteField(hpack.HeaderField{Name: h[0], Value: h[1]})
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hb.Bytes(), EndStream: true, EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestParseRealFrames(t *testing.T) {
	p, ok := Parse(chromeLikePreface(t, 0))
	if !ok {
		t.Fatal("parse failed")
	}
	if got := p.String(); got != "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p" {
		t.Fatalf("print %s", got)
	}
	if Classify(p) != "chrome" {
		t.Fatalf("class %s", Classify(p))
	}
	p, _ = Parse(chromeLikePreface(t, 2))
	if p.Priority != 2 {
		t.Fatalf("priority frames %d", p.Priority)
	}
	// Truncated input waits for more bytes rather than guessing.
	full := chromeLikePreface(t, 0)
	if _, ok := Parse(full[:len(full)-3]); ok {
		t.Fatal("truncated HEADERS produced a print")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(chromeLikePreface(f, 1))
	f.Add([]byte(preface))
	f.Fuzz(func(t *testing.T, b []byte) {
		if p, ok := Parse(b); ok {
			_ = Classify(p)
		}
	})
}
