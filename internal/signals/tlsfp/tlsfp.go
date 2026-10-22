// Package tlsfp computes JA4 TLS client fingerprints (design section 3.1)
// when doorkeep terminates TLS itself. A recording net.Conn copies the bytes
// Go's crypto/tls reads during the handshake; the ClientHello is parsed from
// that copy, so nothing is replayed and ALPN/HTTP/2 work unchanged.
//
// JA4 is used rather than JA3 because Chrome randomises TLS extension order,
// which breaks JA3; JA4 sorts ciphers and extensions.
package tlsfp

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

// Hello is the subset of a ClientHello JA4 needs.
type Hello struct {
	Version           uint16 // legacy_version
	Ciphers           []uint16
	Extensions        []uint16 // in wire order
	SNI               string
	ALPN              []string
	SupportedVersions []uint16
	SigAlgs           []uint16
}

var errShort = errors.New("tlsfp: short ClientHello")

// isGREASE reports RFC 8701 GREASE values (0x?a?a with equal bytes).
func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

// ParseRecords parses one or more TLS records carrying a ClientHello.
func ParseRecords(b []byte) (*Hello, error) {
	var hs []byte
	for len(b) >= 5 {
		if b[0] != 22 { // handshake
			return nil, errors.New("tlsfp: not a handshake record")
		}
		n := int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < 5+n {
			return nil, errShort
		}
		hs = append(hs, b[5:5+n]...)
		b = b[5+n:]
		if len(hs) >= 4 && len(hs) >= 4+int(uint32(hs[1])<<16|uint32(hs[2])<<8|uint32(hs[3])) {
			break
		}
	}
	return ParseHandshake(hs)
}

// ParseHandshake parses a ClientHello handshake message.
func ParseHandshake(hs []byte) (*Hello, error) {
	if len(hs) < 4 || hs[0] != 1 {
		return nil, errors.New("tlsfp: not a ClientHello")
	}
	l := int(uint32(hs[1])<<16 | uint32(hs[2])<<8 | uint32(hs[3]))
	if len(hs) < 4+l {
		return nil, errShort
	}
	p := hs[4 : 4+l]
	r := reader{b: p}
	h := &Hello{}
	h.Version = r.u16()
	r.skip(32) // random
	r.skip(int(r.u8()))
	cl := int(r.u16())
	for i := 0; i < cl/2; i++ {
		h.Ciphers = append(h.Ciphers, r.u16())
	}
	r.skip(int(r.u8())) // compression methods
	if r.err != nil {
		return nil, r.err
	}
	if r.left() == 0 {
		return h, nil
	}
	el := int(r.u16())
	ext := reader{b: r.bytes(el)}
	for ext.left() >= 4 && ext.err == nil {
		typ := ext.u16()
		data := reader{b: ext.bytes(int(ext.u16()))}
		h.Extensions = append(h.Extensions, typ)
		switch typ {
		case 0x0000: // server_name
			data.skip(2)
			if data.u8() == 0 {
				h.SNI = string(data.bytes(int(data.u16())))
			}
		case 0x0010: // ALPN
			list := reader{b: data.bytes(int(data.u16()))}
			for list.left() > 0 && list.err == nil {
				h.ALPN = append(h.ALPN, string(list.bytes(int(list.u8()))))
			}
		case 0x002b: // supported_versions
			n := int(data.u8())
			for i := 0; i < n/2; i++ {
				h.SupportedVersions = append(h.SupportedVersions, data.u16())
			}
		case 0x000d: // signature_algorithms
			n := int(data.u16())
			for i := 0; i < n/2; i++ {
				h.SigAlgs = append(h.SigAlgs, data.u16())
			}
		}
	}
	if r.err != nil || ext.err != nil {
		return nil, errShort
	}
	return h, nil
}

// JA4 returns the JA4 fingerprint (TCP) per the FoxIO specification.
func (h *Hello) JA4() string {
	ver := h.Version
	for _, v := range h.SupportedVersions {
		if !isGREASE(v) && v > ver {
			ver = v
		}
	}
	vs := map[uint16]string{0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}[ver]
	if vs == "" {
		vs = "00"
	}
	sni := "i"
	if h.SNI != "" {
		sni = "d"
	}
	var ciphers, exts []string
	for _, c := range h.Ciphers {
		if !isGREASE(c) {
			ciphers = append(ciphers, fmt.Sprintf("%04x", c))
		}
	}
	nExt := 0
	for _, e := range h.Extensions {
		if isGREASE(e) {
			continue
		}
		nExt++
		if e != 0x0000 && e != 0x0010 {
			exts = append(exts, fmt.Sprintf("%04x", e))
		}
	}
	alpn := "00"
	if len(h.ALPN) > 0 && h.ALPN[0] != "" {
		alpn = alpnCode(h.ALPN[0])
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s", vs, sni, min(len(ciphers), 99), min(nExt, 99), alpn)

	sort.Strings(ciphers)
	b := trunc(strings.Join(ciphers, ","))
	if len(ciphers) == 0 {
		b = "000000000000"
	}
	sort.Strings(exts)
	cs := strings.Join(exts, ",")
	var sigs []string
	for _, s := range h.SigAlgs {
		if !isGREASE(s) {
			sigs = append(sigs, fmt.Sprintf("%04x", s))
		}
	}
	if len(sigs) > 0 {
		cs += "_" + strings.Join(sigs, ",")
	}
	c := trunc(cs)
	if len(exts) == 0 {
		c = "000000000000"
	}
	return a + "_" + b + "_" + c
}

// alpnCode is JA4's two-character ALPN field: the first and last
// characters of the first ALPN value, or, if either is not alphanumeric,
// the first and last characters of the value's hex encoding (FoxIO spec).
func alpnCode(a string) string {
	alnum := func(c byte) bool { return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }
	if alnum(a[0]) && alnum(a[len(a)-1]) {
		return string(a[0]) + string(a[len(a)-1])
	}
	x := hex.EncodeToString([]byte(a))
	return string(x[0]) + string(x[len(x)-1])
}

// OffersH2 reports whether the client offered HTTP/2 in ALPN.
func (h *Hello) OffersH2() bool {
	for _, a := range h.ALPN {
		if a == "h2" {
			return true
		}
	}
	return false
}

func trunc(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) left() int { return len(r.b) }
func (r *reader) need(n int) bool {
	if r.err != nil || n < 0 || len(r.b) < n {
		r.err = errShort
		return false
	}
	return true
}
func (r *reader) u8() uint8 {
	if !r.need(1) {
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}
func (r *reader) u16() uint16 {
	if !r.need(2) {
		return 0
	}
	v := binary.BigEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v
}
func (r *reader) bytes(n int) []byte {
	if !r.need(n) {
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}
func (r *reader) skip(n int) { r.bytes(n) }

// ---------------- recording conn and listener ----------------

const maxHello = 64 << 10

// Conn records the first bytes read until a full ClientHello is seen.
type Conn struct {
	net.Conn
	mu    sync.Mutex
	buf   []byte
	done  bool
	hello *Hello
}

func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		if !c.done {
			c.buf = append(c.buf, p[:n]...)
			if h, perr := ParseRecords(c.buf); perr == nil {
				c.hello, c.done, c.buf = h, true, nil
			} else if !errors.Is(perr, errShort) || len(c.buf) > maxHello {
				c.done, c.buf = true, nil
			}
		}
		c.mu.Unlock()
	}
	return n, err
}

// Hello returns the parsed ClientHello, or nil if unavailable.
func (c *Conn) Hello() *Hello {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hello
}

// Listener wraps accepted connections in *Conn.
type Listener struct{ net.Listener }

func (l Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &Conn{Conn: c}, nil
}

// Classes of JA4 cipher-list hashes, measured from real clients on
// 2026-10-22 (testing/tlsclients/measure). TLS separates browsers from HTTP
// libraries; it does not separate browsers from each other (Firefox 157 and
// Chromium share a cipher list), HTTP/2 does that.
var cipherClass = map[string]string{
	"8daaf6152771": "browser", // Chromium 15x, Firefox 157
	"5b57614c22b0": "browser", // Firefox up to ~13x
	"a09f3c656075": "browser", // Safari / Apple platform TLS (published)
	"1d37bd780c83": "openssl", // curl, Python urllib/requests (OpenSSL 3)
	"f57a46bbacb6": "go",      // Go crypto/tls
	"b262b3658495": "node",    // Node.js fetch (undici)
}

// Class maps a JA4 string to browser | openssl | go | node | other | none.
func Class(ja4 string) string {
	if ja4 == "" {
		return "none"
	}
	parts := strings.Split(ja4, "_")
	if len(parts) != 3 {
		return "other"
	}
	if c, ok := cipherClass[parts[1]]; ok {
		return c
	}
	return "other"
}
