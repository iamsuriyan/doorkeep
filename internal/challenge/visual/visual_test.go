package visual

import (
	"bytes"
	"image/png"
	"os"
	"strings"
	"testing"
)

func gen() *Generator { return New(bytes.Repeat([]byte{9}, 32)) }

func TestAnswerDeterministicAndScoped(t *testing.T) {
	g := gen()
	a := g.Answer("nonce-1")
	if a != g.Answer("nonce-1") {
		t.Fatal("answer not deterministic")
	}
	if a == g.Answer("nonce-2") && a == g.Answer("nonce-3") {
		t.Fatal("answers do not vary by nonce")
	}
	if len(a) != Length {
		t.Fatal("length")
	}
	for _, c := range a {
		if !strings.ContainsRune(Alphabet, c) {
			t.Fatalf("char %q outside alphabet", c)
		}
	}
	if New(bytes.Repeat([]byte{1}, 32)).Answer("nonce-1") == a && New(bytes.Repeat([]byte{2}, 32)).Answer("nonce-1") == a {
		t.Fatal("answer does not depend on the key")
	}
}

func TestNormalise(t *testing.T) {
	if Normalise(" ac d-3 ") != "ACD3" {
		t.Fatal(Normalise(" ac d-3 "))
	}
	if Normalise("xqpnp") != "X4PNP" {
		t.Fatal(Normalise("xqpnp"))
	}
}

func TestPNG(t *testing.T) {
	g := gen()
	b, err := g.PNG("nonce-1")
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil || img.Bounds().Dx() != 260 {
		t.Fatalf("png: %v", err)
	}
	b2, _ := g.PNG("nonce-1")
	if !bytes.Equal(b, b2) {
		t.Fatal("image not deterministic per nonce")
	}
	if dir := os.Getenv("DOORKEEP_DUMP_CHALLENGE"); dir != "" {
		os.WriteFile(dir+"/challenge.png", b, 0o644)
		w, _ := g.WAV("nonce-1", false)
		os.WriteFile(dir+"/challenge.wav", w, 0o644)
		t.Logf("answer for dumped media: %s", g.Answer("nonce-1"))
	}
}

func TestWAV(t *testing.T) {
	g := gen()
	b, err := g.WAV("nonce-1", false)
	if err != nil {
		t.Fatal(err)
	}
	s := wavSamples(b)
	secs := float64(len(s)) / sampleRate
	if secs < 2 || secs > 12 {
		t.Fatalf("audio length %.1fs", secs)
	}
	slow, _ := g.WAV("nonce-1", true)
	if len(wavSamples(slow)) <= len(s) {
		t.Fatal("slower audio is not longer")
	}
	for _, v := range voices {
		for _, c := range Alphabet {
			if pcm, err := clip(v, c); err != nil || len(pcm) < 800 {
				t.Fatalf("clip %s %c missing or too short (%d samples)", v, c, len(pcm))
			}
		}
	}
}

func TestNormaliseMapsOntoAlphabet(t *testing.T) {
	for in, want := range map[string]string{" a-c d ": "ACD", "1i": "LL", "q": "4", "x7": "X7"} {
		if got := Normalise(in); got != want {
			t.Errorf("Normalise(%q) = %q, want %q", in, got, want)
		}
	}
	// Every mapping target is in the alphabet.
	for _, c := range Normalise("1IQ") {
		if !strings.ContainsRune(Alphabet, c) {
			t.Errorf("%q maps outside the alphabet", c)
		}
	}
}
