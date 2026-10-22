package ipintel

import (
	"bytes"
	"compress/gzip"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

const tsv = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n" +
	"3.0.0.0\t3.255.255.255\t16509\tUS\tAMAZON-02\n" +
	"49.32.0.0\t49.47.255.255\t55836\tIN\tRELIANCEJIO-IN Reliance Jio Infocomm Limited\n" +
	"128.232.0.0\t128.232.255.255\t786\tGB\tJANET Jisc Services Limited UNIVERSITY\n" +
	"203.0.113.0\t203.0.113.255\t0\tNone\tNot routed\n" +
	"2a01:4f8::\t2a01:4f8:ffff:ffff:ffff:ffff:ffff:ffff\t24940\tDE\tHETZNER-AS\n"

func writeFixture(t *testing.T) string {
	dir := t.TempDir()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(tsv))
	gz.Close()
	os.WriteFile(filepath.Join(dir, FileASN), buf.Bytes(), 0o600)
	os.WriteFile(filepath.Join(dir, FileTor), []byte("185.220.101.1\n"), 0o600)
	os.WriteFile(filepath.Join(dir, FileDropV4), []byte(`{"cidr":"192.0.2.0/24","sblid":"SBL1"}`+"\n"+`{"type":"metadata"}`), 0o600)
	os.WriteFile(filepath.Join(dir, FileCrawlers), []byte(`{"googlebot":["66.249.66.0/27"]}`), 0o600)
	return dir
}

func TestLookup(t *testing.T) {
	db, err := Load(writeFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ip    string
		asn   uint32
		cc    string
		class string
	}{
		{"3.4.5.6", 16509, "us", "hosting"},
		{"49.36.1.1", 55836, "in", "mobile"},
		{"128.232.1.1", 786, "gb", "edu"},
		{"1.0.0.1", 13335, "us", "isp"},
		{"203.0.113.9", 0, "", "unknown"},
		{"9.9.9.9", 0, "", "unknown"},
		{"2a01:4f8:1::1", 24940, "de", "hosting"},
		{"::ffff:3.4.5.6", 16509, "us", "hosting"},
	}
	for _, c := range cases {
		got := db.Lookup(netip.MustParseAddr(c.ip))
		if got.ASN != c.asn || got.Country != c.cc || got.Class != c.class {
			t.Errorf("%s: got %+v", c.ip, got)
		}
	}
	if !db.Lookup(netip.MustParseAddr("185.220.101.1")).Tor {
		t.Error("tor exit missed")
	}
	if !db.Lookup(netip.MustParseAddr("192.0.2.77")).Drop {
		t.Error("DROP range missed")
	}
	if db.Lookup(netip.MustParseAddr("66.249.66.5")).Crawler != "googlebot" {
		t.Error("googlebot range missed")
	}
}

func TestEmptyDirIsUsable(t *testing.T) {
	db, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := db.Lookup(netip.MustParseAddr("3.4.5.6")); got.Class != "unknown" {
		t.Fatalf("%+v", got)
	}
}
