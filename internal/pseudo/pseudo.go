// Package pseudo derives the pseudonymous identifiers doorkeep stores
// (design section 6.2). By construction:
//   - the same device yields different fingerprint hashes on different sites
//     and in different months, so neither doorkeep nor its operator can link
//     a visitor across sites or over long periods;
//   - IP hashes are scoped to one day and to a /24 (IPv4) or /48 (IPv6).
// Rotating the instance secret cuts all linkage.
package pseudo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Keyer derives scoped keys from the instance secret.
type Keyer struct {
	secret []byte
}

// New returns a Keyer. secret must be at least 32 bytes.
func New(secret []byte) *Keyer {
	if len(secret) < 32 {
		panic("pseudo: instance secret must be >= 32 bytes")
	}
	return &Keyer{secret: append([]byte(nil), secret...)}
}

func (k *Keyer) derive(info string) []byte {
	out := make([]byte, 32)
	r := hkdf.New(sha256.New, k.secret, nil, []byte(info))
	if _, err := io.ReadFull(r, out); err != nil {
		panic(err)
	}
	return out
}

func mac(key []byte, parts ...string) []byte {
	h := hmac.New(sha256.New, key)
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

// FPInput is the stable, bucketed device description hashed into fp_hash.
type FPInput struct {
	CanvasHash string
	GLHash     string
	FontMask   string
	ScreenKey  string
	TZ         string
	Langs      []string
	UAFamily   string
	OSFamily   string
	HCBucket   int
}

// FPHash returns a 16-byte hex fingerprint hash scoped to site and month.
func (k *Keyer) FPHash(siteID string, at time.Time, in FPInput) string {
	key := k.derive("fp|" + siteID + "|" + at.UTC().Format("2006-01"))
	sum := mac(key, in.CanvasHash, in.GLHash, in.FontMask, in.ScreenKey, in.TZ,
		strings.Join(in.Langs, ","), in.UAFamily, in.OSFamily, string(rune('0'+in.HCBucket)))
	return hex.EncodeToString(sum[:16])
}

// Prefix returns the /24 (IPv4) or /48 (IPv6) prefix string of addr.
func Prefix(addr netip.Addr) string {
	addr = addr.Unmap()
	bits := 24
	if addr.Is6() {
		bits = 48
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
}

// IPHash returns a 16-byte hex hash of the address prefix scoped to the day.
func (k *Keyer) IPHash(addr netip.Addr, at time.Time) string {
	key := k.derive("ip|" + at.UTC().Format("2006-01-02"))
	sum := mac(key, Prefix(addr))
	return hex.EncodeToString(sum[:16])
}

// UAHash is a short non-keyed hash used only to compare the UA between
// session issue and submit within one nonce lifetime.
func UAHash(ua string) string {
	s := sha256.Sum256([]byte(ua))
	return hex.EncodeToString(s[:8])
}

// SeedHash hashes a nonce seed for canvas replay tracking.
func (k *Keyer) SeedHash(seed string) string {
	sum := mac(k.derive("seed"), seed)
	return hex.EncodeToString(sum[:8])
}

// AnswerMAC binds a visual challenge answer to a nonce.
func (k *Keyer) AnswerMAC(nonceID, answer string) string {
	sum := mac(k.derive("answer"), nonceID, strings.ToUpper(strings.TrimSpace(answer)))
	return hex.EncodeToString(sum)
}

// SecretHash hashes a site secret for storage and lookup. Secrets are 32
// random bytes, so a fast hash is appropriate.
func SecretHash(secret string) string {
	s := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(s[:])
}
