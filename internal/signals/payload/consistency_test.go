package payload

import (
	"encoding/base64"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
	_ "time/tzdata"
)

func mask(bits ...int) string {
	b := make([]byte, 3)
	for _, i := range bits {
		b[i/8] |= 1 << (i % 8)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestFontClassAndMismatch(t *testing.T) {
	cases := []struct {
		mask     string
		class    string
		os       string
		mismatch bool
	}{
		{mask(0, 1, 4), "windows", "windows", false},
		{mask(0, 1, 4), "windows", "macos", true},
		{mask(6, 7, 9), "macos", "macos", false},
		{mask(6, 7, 9), "macos", "windows", true},
		{mask(12, 13), "android", "android", false},
		{mask(16, 17), "linux-bare", "windows", true}, // headless Linux claiming Windows
		{mask(16, 18), "linux-desktop", "linux", false},
		{mask(12, 16), "linux-bare", "linux", false}, // Android-ish fonts on Linux are common
		{mask(0, 6), "mixed", "windows", false},      // mixed sets are neutral
		{mask(), "none", "windows", false},
	}
	for _, c := range cases {
		if got := fontOSClass(c.mask); got != c.class {
			t.Errorf("mask %s: class %s, want %s", c.mask, got, c.class)
		}
		if got := fontMismatch(fontOSClass(c.mask), c.os); got != c.mismatch {
			t.Errorf("%s fonts claiming %s: mismatch %v", c.class, c.os, got)
		}
	}
}

func TestGPUChecks(t *testing.T) {
	if gpuClass(nil, false) != "blocked" || gpuClass([]string{"", ""}, false) != "none" {
		t.Fatal("blocked/none")
	}
	if gpuClass([]string{"Google Inc.", "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device))"}, false) != "software" {
		t.Fatal("SwiftShader not software")
	}
	if gpuClass([]string{"Google Inc. (NVIDIA)", "ANGLE (NVIDIA, GeForce RTX 3060 Direct3D11)"}, false) != "hardware" {
		t.Fatal("hardware GPU")
	}
	if !gpuOSMismatch([]string{"Apple", "Apple M2"}, "windows") || !gpuOSMismatch([]string{"x", "ANGLE (Direct3D11)"}, "macos") {
		t.Fatal("GPU/OS contradiction not flagged")
	}
	if gpuOSMismatch([]string{"Apple", "Apple M2"}, "macos") || gpuOSMismatch(nil, "windows") {
		t.Fatal("consistent or blocked GPU flagged")
	}
}

func TestClientHintsMismatch(t *testing.T) {
	win := Classified{OSFamily: "windows"}
	if uadMismatch(&UAD{Platform: "Windows"}, win) {
		t.Fatal("consistent hints flagged")
	}
	if !uadMismatch(&UAD{Platform: "macOS"}, win) || !uadMismatch(&UAD{Mobile: true}, win) {
		t.Fatal("contradicting hints not flagged")
	}
	if uadMismatch(&UAD{Mobile: false}, Classified{OSFamily: "android", Mobile: true}) {
		t.Fatal("Android tablets report mobile=false; must be neutral")
	}
}

func TestFeatureProbes(t *testing.T) {
	all := make([]int, len(probes))
	for i := range all {
		all[i] = i
	}
	full := mask(all...)
	if n := featMismatch("chrome", 130, full); n != 0 {
		t.Fatalf("modern Chrome with every feature: %d mismatches", n)
	}
	// A "Chrome 130" missing post-110 features is an older engine in disguise.
	if n := featMismatch("chrome", 130, mask(0, 1, 2, 3, 4)); n < 5 {
		t.Fatalf("old engine claiming Chrome 130: %d mismatches", n)
	}
	// Claiming an old version while having new features is also a contradiction.
	if n := featMismatch("chrome", 90, full); n == 0 {
		t.Fatal("Chrome 90 with Chrome 122 features not flagged")
	}
	if featMismatch("chrome", 0, full) != 0 || featMismatch("chrome", 130, "") != 0 {
		t.Fatal("unknown version or probes must be neutral")
	}
}

// The snippet's probe and font lists must stay in step with the server's
// tables: a reorder silently corrupts every consistency check.
func TestProbeTablesMatchSnippet(t *testing.T) {
	src, err := os.ReadFile("../../../web/snippet/src/schema.ts")
	if err != nil {
		t.Skip("snippet source not available:", err)
	}
	s := string(src)
	feat := s[strings.Index(s, "FEATURE_PROBES"):]
	feat = feat[:strings.Index(feat, "];")]
	lines := regexp.MustCompile(`(?m)^\s*\(\) =>.*$`).FindAllString(feat, -1)
	if len(lines) != len(probes) {
		t.Fatalf("snippet has %d feature probes, server %d", len(lines), len(probes))
	}
	for i, p := range probes {
		name := p.name[strings.LastIndex(p.name, ".")+1:]
		if !strings.Contains(lines[i], name) {
			t.Errorf("probe %d: server %q, snippet %s", i, p.name, strings.TrimSpace(lines[i]))
		}
	}
	fonts := s[strings.Index(s, "FONT_PROBES = ["):]
	fonts = fonts[:strings.Index(fonts, "];")]
	if n := len(regexp.MustCompile(`"[^"]+"`).FindAllString(fonts, -1)); n != 20 {
		t.Fatalf("snippet has %d font probes; the server masks assume 20", n)
	}
}

// tzStdOffsets is hand-maintained; check it against the IANA database.
func TestTZTableMatchesTZData(t *testing.T) {
	year := time.Now().Year()
	for zone, off := range tzStdOffsets {
		loc, err := time.LoadLocation(zone)
		if err != nil {
			t.Errorf("%s: %v", zone, err)
			continue
		}
		_, jan := time.Date(year, 1, 15, 12, 0, 0, 0, loc).Zone()
		_, jul := time.Date(year, 7, 15, 12, 0, 0, 0, loc).Zone()
		if std := min(jan, jul) / 60; std != off {
			t.Errorf("%s: table %d, tzdata standard offset %d", zone, off, std)
		}
	}
}

func TestTimezoneOffsetMismatch(t *testing.T) {
	check := func(tz string, tzo float64) (bool, bool) {
		p := &Payload{V: 1, N: "aaaaaaaaaaaaaaaaaaaaaa", FP: FP{TZ: tz, TZO: tzo}}
		f, _ := Normalise(p, ServerContext{})
		return f.Get("fp.tz_offset_mismatch") == 1, f.Has("fp.tz_offset_mismatch")
	}
	if m, _ := check("Asia/Kolkata", -330); m {
		t.Fatal("consistent zone flagged")
	}
	if m, _ := check("Europe/Berlin", -120); m {
		t.Fatal("summer time (+60) flagged")
	}
	if m, _ := check("Asia/Kolkata", 300); !m {
		t.Fatal("Kolkata with a US offset not flagged")
	}
	if _, set := check("Mars/Olympus_Mons", 0); set {
		t.Fatal("unknown zone must be neutral")
	}
}

// FuzzDecode checks the payload decoder never panics and that whatever it
// accepts normalises without panicking.
func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"v":1,"n":"aaaaaaaaaaaaaaaaaaaaaa"}`))
	f.Add([]byte(`{"v":1,"n":"aaaaaaaaaaaaaaaaaaaaaa","fp":{"ua":"x","tz":"UTC","fn":"PwAAAA","feat":"_w8"},"beh":{"ptr":[1,2,3]}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := DecodeBytes(b)
		if err != nil {
			return
		}
		Normalise(p, ServerContext{ElapsedMS: 5000, NowMS: 1.8e12})
	})
}
