// Package payload defines the wire schema the browser snippet posts to
// /v1/submit, decodes it defensively, and normalises it into the scoring
// feature vector.
//
// The Go struct mirrors `interface Payload` in web/snippet/src/schema.ts.
// Short keys are intentional (size); both sides must change together and
// bump Version.
package payload

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
)

// Version is the schema version the server accepts.
const Version = 1

// MaxBytes bounds the request body; a genuine payload is 2-4 KB.
const MaxBytes = 32 * 1024

// Limits on variable-length fields, enforced by Validate.
const (
	maxUA       = 512
	maxTZ       = 64
	maxLangs    = 5
	maxLangLen  = 16
	maxAction   = 64
	maxGL       = 256
	maxHashB64  = 44 // 32 bytes base64url max; we expect 11 (8 bytes)
	maxFontB64  = 8  // 40-bit mask -> 7 chars
	maxFeatB64  = 12 // up to 64 probes
	maxBrands   = 6
	maxBrandLen = 64
	maxStats    = 32 // per behaviour array
)

// Payload is the top-level wire object.
type Payload struct {
	V    int     `json:"v"`
	N    string  `json:"n"` // nonce id, base64url 16 bytes
	A    string  `json:"a"` // action
	T    Timing  `json:"t"`
	Prof Profile `json:"prof"`
	Auto Auto    `json:"auto"`
	FP   FP      `json:"fp"`
	Beh  Beh     `json:"beh"`
	Env  Env     `json:"env"`
}

// Timing carries client clocks. I, F and S are performance.now() values (ms
// since timeOrigin); D is the client's Date.now() at submit (unix ms) so the
// server can compute wall-clock skew.
type Timing struct {
	I float64 `json:"i"` // init
	F float64 `json:"f"` // first trusted interaction (0 = none)
	S float64 `json:"s"` // submit
	D float64 `json:"d"` // Date.now() at submit, unix ms
}

// Profile holds privacy-browser hints. Informational only.
type Profile struct {
	RFP          bool `json:"rfp"`
	Brave        bool `json:"brave"`
	Tor          bool `json:"tor"`
	DNT          bool `json:"dnt"`
	ForcedColors bool `json:"fc"`
}

// Auto holds automation markers (design section 1.2 A).
type Auto struct {
	WD     int       `json:"wd"`     // 0 false, 1 true, 2 undefined/missing
	WDT    int       `json:"wdt"`    // tamper bitmask: 1 descriptor missing, 2 non-native getter, 4 realm mismatch, 8 Function.toString patched
	CDP    bool      `json:"cdp"`    // Runtime.enable artefact fired
	Leaks  int       `json:"leaks"`  // count of known automation globals
	HUA    bool      `json:"hua"`    // HeadlessChrome in UA/brands
	Geo    []float64 `json:"geo"`    // [innerW, innerH, outerW, outerH, fullscreen(0/1)]
	Plg    []int     `json:"plg"`    // [plugins.length, shapeClass]
	Chr    int       `json:"chr"`    // window.chrome class 0..3
	Notif  bool      `json:"notif"`  // notification permission contradiction
	Conn   int       `json:"conn"`   // 0 n/a, 1 rtt>0, 2 rtt==0
	Voices int       `json:"voices"` // -1 n/a, else count
	Eng    int       `json:"eng"`    // 0 v8, 1 spidermonkey, 2 jsc, 3 other
	Nat    int       `json:"nat"`    // count of non-native core APIs
}

// UAD mirrors navigator.userAgentData.
type UAD struct {
	Brands   []string `json:"b"`
	Platform string   `json:"p"`
	Mobile   bool     `json:"m"`
}

// Canvas carries two canvas hashes and the blocked flag. H is drawn with
// the session seed and binds the payload to its nonce (replay detection); S
// is drawn with fixed content and is the stable device component used for
// fingerprint velocity. Without S a real device would get a new
// fingerprint every session.
type Canvas struct {
	H string `json:"h"`           // seeded, base64url truncated SHA-256 (8 bytes)
	S string `json:"s,omitempty"` // static, same encoding
	B bool   `json:"b"`           // blank / blocked
}

// FP holds fingerprint-consistency inputs (design section 1.2 B).
type FP struct {
	UA   string    `json:"ua"`
	UAD  *UAD      `json:"uad,omitempty"`
	Scr  []float64 `json:"scr"` // [width, height, availWidth, availHeight, colorDepth, dpr, orientationClass]
	TZ   string    `json:"tz"`
	TZO  float64   `json:"tzo"` // getTimezoneOffset() minutes
	Lang []string  `json:"lang"`
	GL   []string  `json:"gl,omitempty"` // [vendor, renderer]; nil = unavailable
	CV   Canvas    `json:"cv"`
	AU   string    `json:"au,omitempty"` // audio hash
	FN   string    `json:"fn,omitempty"` // font bitmask base64url (40 bits)
	HC   int       `json:"hc"`
	DM   float64   `json:"dm,omitempty"`
	Tch  int       `json:"tch"`  // bitmask: 1 maxTouchPoints>0, 2 ontouchstart, 4 pointer:coarse, 8 hover:none, 16 any-pointer:fine
	MQ   int       `json:"mq"`   // bitmask: 1 dark, 2 reduced-motion, 4 forced-colors, 8 gamut p3+
	Feat string    `json:"feat"` // probe bitmask base64url
	MTP  int       `json:"mtp"`  // maxTouchPoints
}

// Beh holds behaviour aggregates (design section 1.2 C). Arrays are fixed
// positional vectors documented in schema.ts; absent/empty = no data.
//
//	ptr: [samples, pathLen, straightness, speedCV, dirChanges, accelFlips,
//	      intervalCV, collinearFrac, untrustedFrac, h0..h5 (interval histogram)]
//	clk: [count, durMean, durCV, centerFrac, noMoveClick(0/1)]
//	key: [count, holdMean, holdCV, intervalCV, backspaceFrac, inputNoKeyFrac, pasteCount]
//	scr: [count, wheelClass, scrolledBeforeFirstInteraction(0/1)]
//	foc: [focusStart(0/1), focusSubmit(0/1), visibilityChanges, hiddenAtSubmit(0/1)]
//	raf: [median, cv]
type Beh struct {
	Ptr []float64 `json:"ptr"`
	Clk []float64 `json:"clk"`
	Key []float64 `json:"key"`
	Scr []float64 `json:"scr"`
	Foc []float64 `json:"foc"`
	Raf []float64 `json:"raf,omitempty"`
}

// Env holds environment signals (design section 1.2 D).
//
//	perm: 2 bits per permission in order notifications, geolocation, camera,
//	      microphone, clipboard-read: 0 unsupported, 1 prompt, 2 granted, 3 denied
//	sto:  bitmask: 1 localStorage ok, 2 sessionStorage ok, 4 indexedDB ok,
//	      8 cookies enabled, 16 a storage API threw
//	perf: [timerPrecisionClass, domReadyMs, resourceCount, navigationType]
//	integ: bitmask of non-native core APIs (same as auto.nat but positional)
//	quota: storage.estimate().quota in MB (0 = n/a)
//	sv: snippet build version
type Env struct {
	Perm  int       `json:"perm"`
	Sto   int       `json:"sto"`
	Perf  []float64 `json:"perf"`
	Integ int       `json:"integ"`
	Quota float64   `json:"quota"`
	SV    int       `json:"sv"`
}

// ErrInvalid wraps all validation failures.
var ErrInvalid = errors.New("payload: invalid")

// Decode reads and validates a payload from r (bounded by MaxBytes).
func Decode(r io.Reader) (*Payload, error) {
	lr := io.LimitReader(r, MaxBytes+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("%w: read: %v", ErrInvalid, err)
	}
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("%w: body exceeds %d bytes", ErrInvalid, MaxBytes)
	}
	return DecodeBytes(data)
}

// DecodeBytes parses and validates a payload.
func DecodeBytes(data []byte) (*Payload, error) {
	var p Payload
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%w: json: %v", ErrInvalid, err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate enforces schema version, field lengths and numeric sanity. It
// never rejects for "suspicious" values; that is the scorer's job. It rejects
// only what a conforming snippet cannot produce.
func (p *Payload) Validate() error {
	if p.V != Version {
		return fmt.Errorf("%w: schema version %d", ErrInvalid, p.V)
	}
	if l := len(p.N); l < 16 || l > 32 {
		return fmt.Errorf("%w: nonce length %d", ErrInvalid, l)
	}
	if len(p.A) > maxAction {
		return fmt.Errorf("%w: action too long", ErrInvalid)
	}
	if p.A == "" {
		p.A = "default"
	}
	for _, v := range []float64{p.T.I, p.T.F, p.T.S, p.T.D} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1e14 {
			return fmt.Errorf("%w: timing out of range", ErrInvalid)
		}
	}
	if len(p.FP.UA) > maxUA || len(p.FP.TZ) > maxTZ {
		return fmt.Errorf("%w: ua/tz too long", ErrInvalid)
	}
	if len(p.FP.Lang) > maxLangs {
		p.FP.Lang = p.FP.Lang[:maxLangs]
	}
	for i, l := range p.FP.Lang {
		if len(l) > maxLangLen {
			p.FP.Lang[i] = l[:maxLangLen]
		}
	}
	if p.FP.GL != nil {
		if len(p.FP.GL) != 2 {
			return fmt.Errorf("%w: gl shape", ErrInvalid)
		}
		for i := range p.FP.GL {
			if len(p.FP.GL[i]) > maxGL {
				p.FP.GL[i] = p.FP.GL[i][:maxGL]
			}
		}
	}
	if p.FP.UAD != nil {
		if len(p.FP.UAD.Brands) > maxBrands {
			p.FP.UAD.Brands = p.FP.UAD.Brands[:maxBrands]
		}
		for i, b := range p.FP.UAD.Brands {
			if len(b) > maxBrandLen {
				p.FP.UAD.Brands[i] = b[:maxBrandLen]
			}
		}
		if len(p.FP.UAD.Platform) > maxBrandLen {
			p.FP.UAD.Platform = p.FP.UAD.Platform[:maxBrandLen]
		}
	}
	if len(p.FP.CV.H) > maxHashB64 || len(p.FP.CV.S) > maxHashB64 || len(p.FP.AU) > maxHashB64 || len(p.FP.FN) > maxFontB64 || len(p.FP.Feat) > maxFeatB64 {
		return fmt.Errorf("%w: hash field too long", ErrInvalid)
	}
	if !isB64URL(p.N) || !isB64URL(p.FP.CV.H) || !isB64URL(p.FP.CV.S) || !isB64URL(p.FP.AU) || !isB64URL(p.FP.FN) || !isB64URL(p.FP.Feat) {
		return fmt.Errorf("%w: non-base64url hash field", ErrInvalid)
	}
	for _, arr := range [][]float64{p.FP.Scr, p.Auto.Geo, p.Beh.Ptr, p.Beh.Clk, p.Beh.Key, p.Beh.Scr, p.Beh.Foc, p.Beh.Raf, p.Env.Perf} {
		if len(arr) > maxStats {
			return fmt.Errorf("%w: stats array too long", ErrInvalid)
		}
		for _, v := range arr {
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return fmt.Errorf("%w: non-finite stat", ErrInvalid)
			}
		}
	}
	if len(p.Auto.Plg) > 2 {
		return fmt.Errorf("%w: plg shape", ErrInvalid)
	}
	if p.Auto.WD < 0 || p.Auto.WD > 2 || p.Auto.Eng < 0 || p.Auto.Eng > 3 || p.Auto.Chr < 0 || p.Auto.Chr > 3 {
		return fmt.Errorf("%w: enum out of range", ErrInvalid)
	}
	return nil
}

func isB64URL(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// at returns arr[i] or NaN when absent.
func at(arr []float64, i int) float64 {
	if i < len(arr) {
		return arr[i]
	}
	return math.NaN()
}
