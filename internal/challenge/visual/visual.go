// Package visual implements the accessible fallback challenge (design
// section 5.2): five characters shown as a distorted image and spoken as a
// noisy audio track. Answers are derived from the nonce with an HMAC, so the
// server stores only a MAC and the same nonce always renders the same media.
//
// Honest framing: a multimodal model can solve any visual or audio captcha
// for a fraction of a cent. This challenge gives humans a path when proof of
// work cannot clear the risk band, and raises an attacker's marginal cost
// from zero to a model call. It is not a security boundary.
package visual

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io/fs"
	"math"
	"math/rand/v2"
	"strings"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

// Alphabet excludes characters that look or sound alike (0/O/Q, 1/I/L is
// kept as L only, 2/Z, 5/S, 6/G/B/8).
const Alphabet = "ACDEFHJKLMNPRTUVWXY3479"

// Length of every answer.
const Length = 5

// Generator derives answers and renders media.
type Generator struct{ key []byte }

// New returns a generator keyed by a 32-byte secret.
func New(key []byte) *Generator { return &Generator{key: append([]byte(nil), key...)} }

func (g *Generator) stream(nonceID, purpose string) *rand.Rand {
	m := hmac.New(sha256.New, g.key)
	m.Write([]byte(purpose + "|" + nonceID))
	sum := m.Sum(nil)
	var seed [32]byte
	copy(seed[:], sum)
	return rand.New(rand.NewChaCha8(seed))
}

// Answer returns the answer for a nonce.
func (g *Generator) Answer(nonceID string) string {
	r := g.stream(nonceID, "answer")
	var b strings.Builder
	for i := 0; i < Length; i++ {
		b.WriteByte(Alphabet[r.IntN(len(Alphabet))])
	}
	return b.String()
}

// Normalise canonicalises user input: case, spaces, and common confusions.
func Normalise(s string) string {
	s = strings.ToUpper(s)
	// Q is not in the alphabet, and the bitmap "4" can look like a "q".
	r := strings.NewReplacer(" ", "", "-", "", "0", "O", "1", "L", "I", "L", "5", "S", "8", "B", "Q", "4")
	return r.Replace(strings.TrimSpace(s))
}

// ---------------- image ----------------

// PNG renders the challenge image for nonceID (deterministic).
func (g *Generator) PNG(nonceID string) ([]byte, error) {
	ans := g.Answer(nonceID)
	r := g.stream(nonceID, "image")
	const W, H, scale = 260, 90, 4
	img := image.NewRGBA(image.Rect(0, 0, W, H))
	bg := color.RGBA{uint8(235 + r.IntN(15)), uint8(235 + r.IntN(15)), uint8(225 + r.IntN(25)), 255}
	draw.Draw(img, img.Bounds(), &image.Uniform{bg}, image.Point{}, draw.Src)

	// Background noise rectangles.
	for i := 0; i < 18; i++ {
		c := color.RGBA{uint8(150 + r.IntN(90)), uint8(150 + r.IntN(90)), uint8(150 + r.IntN(90)), 255}
		x, y := r.IntN(W), r.IntN(H)
		draw.Draw(img, image.Rect(x, y, x+4+r.IntN(22), y+3+r.IntN(10)), &image.Uniform{c}, image.Point{}, draw.Over)
	}
	// Glyphs: render each character from the bitmap face into a small mask,
	// then scale, rotate and wobble it into place.
	face := basicfont.Face7x13
	x0 := 18.0
	for _, ch := range ans {
		mask := image.NewAlpha(image.Rect(0, 0, 8, 14))
		d := &font.Drawer{Dst: mask, Src: image.Opaque, Face: face, Dot: fixed.P(0, 11)}
		d.DrawString(string(ch))
		ang := (r.Float64() - 0.5) * 0.45
		sx := float64(scale) * (0.95 + r.Float64()*0.25)
		sy := float64(scale) * (0.95 + r.Float64()*0.25)
		cx, cy := x0+14, 45+(r.Float64()-0.5)*18
		ink := color.RGBA{uint8(20 + r.IntN(60)), uint8(20 + r.IntN(60)), uint8(60 + r.IntN(90)), 255}
		paintGlyph(img, mask, cx, cy, sx, sy, ang, ink, r.Float64()*6)
		x0 += 44 + float64(r.IntN(6))
	}
	// One strike-through curve.
	for i := 0; i < 1; i++ {
		ink := color.RGBA{uint8(40 + r.IntN(80)), uint8(40 + r.IntN(80)), uint8(40 + r.IntN(80)), 255}
		y0, amp, freq, ph := 25+r.Float64()*40, 6+r.Float64()*10, 0.02+r.Float64()*0.03, r.Float64()*6
		for x := 0; x < W; x++ {
			y := y0 + amp*math.Sin(float64(x)*freq+ph)
			for t := -1; t <= 1; t++ {
				img.Set(x, int(y)+t, ink)
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// paintGlyph maps every destination pixel near (cx,cy) back into the glyph
// mask through an inverse rotate+scale with a sinusoidal wobble.
func paintGlyph(dst *image.RGBA, mask *image.Alpha, cx, cy, sx, sy, ang float64, ink color.RGBA, phase float64) {
	cos, sin := math.Cos(-ang), math.Sin(-ang)
	mw, mh := float64(mask.Bounds().Dx()), float64(mask.Bounds().Dy())
	for y := int(cy - 40); y < int(cy+40); y++ {
		for x := int(cx - 30); x < int(cx+30); x++ {
			dx, dy := float64(x)-cx, float64(y)-cy
			dx += 1.3 * math.Sin(float64(y)/8+phase)
			u := (dx*cos-dy*sin)/sx + mw/2
			v := (dx*sin+dy*cos)/sy + mh/2
			if u < 0 || v < 0 || u >= mw || v >= mh {
				continue
			}
			// Sample a small neighbourhood so 1-pixel bitmap strokes render
			// bold enough to read comfortably.
			if inked(mask, u, v) || inked(mask, u+0.3, v) || inked(mask, u, v+0.3) {
				dst.Set(x, y, ink)
			}
		}
	}
}

func inked(m *image.Alpha, u, v float64) bool {
	b := m.Bounds()
	x, y := int(u), int(v)
	return x >= b.Min.X && y >= b.Min.Y && x < b.Max.X && y < b.Max.Y && m.AlphaAt(x, y).A > 0
}

// ---------------- audio ----------------

//go:embed clips/*.wav
var clipFS embed.FS

const sampleRate = 8000

var voices = []string{"en-us_m3", "en-gb_f3", "en-us_m7"}

func clip(voice string, ch rune) ([]int16, error) {
	b, err := fs.ReadFile(clipFS, "clips/"+voice+"_"+string(ch)+".wav")
	if err != nil {
		return nil, err
	}
	return wavSamples(b), nil
}

// wavSamples extracts 16-bit PCM samples from a RIFF/WAVE file's data chunk.
func wavSamples(b []byte) []int16 {
	if len(b) < 12 || string(b[0:4]) != "RIFF" || string(b[8:12]) != "WAVE" {
		return nil
	}
	p := 12
	for p+8 <= len(b) {
		id, n := string(b[p:p+4]), int(binary.LittleEndian.Uint32(b[p+4:p+8]))
		p += 8
		if id == "data" {
			end := min(p+n, len(b))
			out := make([]int16, 0, (end-p)/2)
			for i := p; i+1 < end; i += 2 {
				out = append(out, int16(binary.LittleEndian.Uint16(b[i:])))
			}
			return out
		}
		p += n + n%2
	}
	return nil
}

// WAV renders the spoken challenge for nonceID: each character in a random
// voice, resampled +-5%, separated by random gaps, over brown noise.
func (g *Generator) WAV(nonceID string, slower bool) ([]byte, error) {
	ans := g.Answer(nonceID)
	r := g.stream(nonceID, "audio")
	var pcm []float64
	gap := func(sec float64) { pcm = append(pcm, make([]float64, int(sec*sampleRate))...) }
	gap(0.5)
	for i, ch := range ans {
		s, err := clip(voices[r.IntN(len(voices))], ch)
		if err != nil {
			return nil, err
		}
		rate := 0.95 + r.Float64()*0.10
		if slower {
			rate *= 0.8
		}
		for t := 0.0; int(t) < len(s)-1; t += rate {
			i0 := int(t)
			f := t - float64(i0)
			pcm = append(pcm, (float64(s[i0])*(1-f)+float64(s[i0+1])*f)/32768)
		}
		if i < len(ans)-1 {
			base := 0.45
			if slower {
				base = 0.8
			}
			gap(base + r.Float64()*0.35)
		}
	}
	gap(0.5)
	// Brown noise at about -24 dB.
	var b float64
	for i := range pcm {
		b = (b + 0.02*(r.Float64()*2-1)) / 1.02
		pcm[i] = pcm[i]*0.85 + b*0.9
	}
	return encodeWAV(pcm), nil
}

func encodeWAV(pcm []float64) []byte {
	data := make([]byte, 2*len(pcm))
	for i, v := range pcm {
		v = math.Max(-1, math.Min(1, v))
		binary.LittleEndian.PutUint16(data[2*i:], uint16(int16(v*32767)))
	}
	var h bytes.Buffer
	h.WriteString("RIFF")
	binary.Write(&h, binary.LittleEndian, uint32(36+len(data)))
	h.WriteString("WAVEfmt ")
	for _, v := range []any{uint32(16), uint16(1), uint16(1), uint32(sampleRate), uint32(sampleRate * 2), uint16(2), uint16(16)} {
		binary.Write(&h, binary.LittleEndian, v)
	}
	h.WriteString("data")
	binary.Write(&h, binary.LittleEndian, uint32(len(data)))
	h.Write(data)
	return h.Bytes()
}
