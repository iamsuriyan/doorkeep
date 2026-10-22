package pseudo

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

func keyer() *Keyer { return New(bytes.Repeat([]byte{7}, 32)) }

func TestFPHashScopedBySiteAndMonth(t *testing.T) {
	k := keyer()
	in := FPInput{CanvasHash: "c", GLHash: "g", Langs: []string{"en"}, UAFamily: "chrome", HCBucket: 2}
	oct := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	a := k.FPHash("s1", oct, in)
	if a != k.FPHash("s1", oct.Add(10*24*time.Hour), in) {
		t.Fatal("same device, same site and month: hashes differ")
	}
	if a == k.FPHash("s2", oct, in) {
		t.Fatal("linkable across sites")
	}
	if a == k.FPHash("s1", oct.AddDate(0, 1, 0), in) {
		t.Fatal("linkable across months")
	}
	if a == New(bytes.Repeat([]byte{8}, 32)).FPHash("s1", oct, in) {
		t.Fatal("rotating the instance secret did not cut linkage")
	}
}

func TestIPHashPrefixAndDay(t *testing.T) {
	k := keyer()
	day := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	a := netip.MustParseAddr("203.0.113.5")
	if k.IPHash(a, day) != k.IPHash(netip.MustParseAddr("203.0.113.200"), day) {
		t.Fatal("same /24 hashed differently")
	}
	if k.IPHash(a, day) == k.IPHash(netip.MustParseAddr("203.0.114.5"), day) {
		t.Fatal("different /24 hashed the same")
	}
	if k.IPHash(a, day) == k.IPHash(a, day.Add(24*time.Hour)) {
		t.Fatal("IP hash not day-scoped")
	}
	v6 := netip.MustParseAddr("2001:db8:1:2::1")
	if k.IPHash(v6, day) != k.IPHash(netip.MustParseAddr("2001:db8:1:ffff::9"), day) {
		t.Fatal("same /48 hashed differently")
	}
	if k.IPHash(netip.MustParseAddr("::ffff:203.0.113.5"), day) != k.IPHash(a, day) {
		t.Fatal("IPv4-mapped address not unmapped")
	}
}

func TestIPHashMatchesAcrossMidnight(t *testing.T) {
	k := keyer()
	a := netip.MustParseAddr("203.0.113.5")
	issued := time.Date(2026, 10, 22, 23, 59, 50, 0, time.UTC)
	h := k.IPHash(a, issued)
	if !k.IPHashMatches(a, h, issued, issued.Add(20*time.Second)) {
		t.Fatal("same address rejected across midnight")
	}
	if k.IPHashMatches(netip.MustParseAddr("198.51.100.1"), h, issued, issued.Add(20*time.Second)) {
		t.Fatal("different address accepted")
	}
}

func TestVelKeyIsKeyedAndStable(t *testing.T) {
	k := keyer()
	first, again := k.VelKey("203.0.113.5"), k.VelKey("203.0.113.5")
	if first != again {
		t.Fatal("not stable")
	}
	if k.VelKey("203.0.113.5") == New(bytes.Repeat([]byte{8}, 32)).VelKey("203.0.113.5") {
		t.Fatal("not keyed by the instance secret")
	}
	if bytes.Contains([]byte(k.VelKey("203.0.113.5")), []byte("203")) {
		t.Fatal("raw address visible in the key")
	}
}

func TestAnswerMACNormalisesCase(t *testing.T) {
	k := keyer()
	if k.AnswerMAC("n", " ab3 ") != k.AnswerMAC("n", "AB3") {
		t.Fatal("answer MAC is case or space sensitive")
	}
	if k.AnswerMAC("n", "AB3") == k.AnswerMAC("m", "AB3") {
		t.Fatal("answer MAC not bound to the nonce")
	}
}

func TestShortSecretPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("short secret accepted")
		}
	}()
	New(make([]byte, 16))
}
