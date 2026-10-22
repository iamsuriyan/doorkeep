package tlsfp

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
)

// The JA4 reference implementation's README worked example: a ClientHello
// with TLS 1.3, SNI, 15 ciphers, 16 extensions, ALPN h2. We cannot embed the
// exact capture here, so this test checks the structural rules instead and
// the live test below checks real clients.
func TestJA4Structure(t *testing.T) {
	h := &Hello{
		Version:           0x0303,
		Ciphers:           []uint16{0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b},
		Extensions:        []uint16{0x1a1a, 0x0000, 0x0017, 0x0010, 0x000d, 0x002b, 0x2a2a},
		SNI:               "example.com",
		ALPN:              []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{0x3a3a, 0x0304, 0x0303},
		SigAlgs:           []uint16{0x0403, 0x0804},
	}
	got := h.JA4()
	if !strings.HasPrefix(got, "t13d0405h2_") {
		t.Fatalf("JA4_a wrong: %s (GREASE must be ignored, TLS 1.3 from supported_versions)", got)
	}
	parts := strings.Split(got, "_")
	if len(parts) != 3 || len(parts[1]) != 12 || len(parts[2]) != 12 {
		t.Fatalf("shape: %s", got)
	}
	// JA4_b is the truncated SHA-256 of sorted non-GREASE ciphers.
	if parts[1] != trunc("1301,1302,1303,c02b") {
		t.Fatalf("JA4_b %s", parts[1])
	}
	// JA4_c excludes SNI and ALPN, sorts the rest, appends sig algs in order.
	if parts[2] != trunc("000d,0017,002b_0403,0804") {
		t.Fatalf("JA4_c %s", parts[2])
	}
	// Extension order must not matter (Chrome randomises it).
	h.Extensions = []uint16{0x002b, 0x000d, 0x0010, 0x0017, 0x0000}
	if h.JA4() != got {
		t.Fatal("JA4 changed with extension order")
	}
}

func TestRecordingConnSeesGoClientHello(t *testing.T) {
	cert := selfSigned(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan *Hello, 1)
	go func() {
		c, err := Listener{ln}.Accept()
		if err != nil {
			return
		}
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
		_ = tc.Handshake()
		got <- c.(*Conn).Hello()
		tc.Close()
	}()
	cc, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, ServerName: "doorkeep.test", NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	cc.Close()
	h := <-got
	if h == nil || h.SNI != "doorkeep.test" || !h.OffersH2() {
		t.Fatalf("hello %+v", h)
	}
	t.Logf("Go crypto/tls client JA4: %s", h.JA4())
	if !strings.HasPrefix(h.JA4(), "t13d") {
		t.Fatalf("unexpected JA4 %s", h.JA4())
	}
}

func TestMalformedNeverPanics(t *testing.T) {
	for _, b := range [][]byte{nil, {22}, {22, 3, 1, 0, 5, 1, 0, 0, 9}, {23, 3, 3, 0, 1, 0}, make([]byte, 300)} {
		_, _ = ParseRecords(b)
	}
}

func FuzzParseRecords(f *testing.F) {
	f.Add([]byte{22, 3, 1, 0, 4, 1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if h, err := ParseRecords(b); err == nil {
			_ = h.JA4()
		}
	})
}
