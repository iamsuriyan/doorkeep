package ipintel

import (
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestLiveData runs only when DOORKEEP_IPDATA_DIR points at real downloaded
// data, to check the parsers against current upstream formats.
func TestLiveData(t *testing.T) {
	dir := os.Getenv("DOORKEEP_IPDATA_DIR")
	if dir == "" {
		t.Skip("set DOORKEEP_IPDATA_DIR to run against live data")
	}
	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	db, err := Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	var after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&after)
	t.Logf("load %s, heap +%d MB, %v", time.Since(start).Round(time.Millisecond), (after.HeapAlloc-before.HeapAlloc)>>20, db.Counts())
	tor, _ := os.ReadFile(dir + "/" + FileTor)
	torIP := strings.TrimSpace(strings.SplitN(string(tor), "\n", 2)[0])
	for _, c := range []struct {
		ip, class string
		asn       uint32
	}{
		{"8.8.8.8", "hosting", 15169},
		{"52.95.110.1", "hosting", 16509},
		{"159.89.0.1", "hosting", 14061},
		{"49.36.0.1", "", 55836},
		{"66.249.66.1", "hosting", 15169},
		{torIP, "", 0},
	} {
		info := db.Lookup(netip.MustParseAddr(c.ip))
		t.Logf("%-15s -> AS%d %s %s tor=%v drop=%v crawler=%q", c.ip, info.ASN, info.Country, info.Class, info.Tor, info.Drop, info.Crawler)
		if c.asn != 0 && info.ASN != c.asn {
			t.Errorf("%s: ASN %d want %d", c.ip, info.ASN, c.asn)
		}
		if c.class != "" && info.Class != c.class {
			t.Errorf("%s: class %s want %s", c.ip, info.Class, c.class)
		}
	}
	if !db.Lookup(netip.MustParseAddr(torIP)).Tor {
		t.Error("first Tor exit not recognised")
	}
	if db.Lookup(netip.MustParseAddr("66.249.66.1")).Crawler != "googlebot" {
		t.Error("googlebot range not recognised")
	}
	n := 0
	t0 := time.Now()
	for i := 0; i < 100000; i++ {
		db.Lookup(netip.AddrFrom4([4]byte{byte(i), byte(i >> 8), 1, 1}))
		n++
	}
	t.Logf("lookup %.1f µs avg", float64(time.Since(t0).Microseconds())/float64(n))
}
