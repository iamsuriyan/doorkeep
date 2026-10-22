// Package ipintel classifies source IPs using only freely redistributable
// data (design section 3.4): ASN and country from iptoasn.com (public
// domain), a curated hosting-ASN list, Tor exits, Spamhaus DROP and the
// crawler ranges search and AI companies publish. Data is downloaded by
// `doorkeep ipdata update` into the data directory; nothing is bundled
// except the curated ASN list. The IP itself is never stored.
package ipintel

import (
	"bufio"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Info is what the scorer learns about an address.
type Info struct {
	ASN     uint32
	Country string // lowercase ISO 3166-1 alpha-2, "" unknown
	Class   string // hosting | isp | mobile | edu | gov | unknown
	Tor     bool
	Drop    bool
	Crawler string // e.g. "googlebot", "" if not a verified crawler range
}

type rng struct {
	start, end netip.Addr
	asn        uint32
	cc         string
}

// DB is an immutable snapshot; Store swaps snapshots atomically.
type DB struct {
	v4, v6   []rng
	desc     map[uint32]string
	hosting  map[uint32]bool
	tor      map[netip.Addr]bool
	drop     []netip.Prefix
	crawlers map[string][]netip.Prefix
	Loaded   time.Time
	Sources  []string
}

// Store holds the current DB for lock-free lookups.
type Store struct{ p atomic.Pointer[DB] }

// Get returns the current snapshot (may be an empty DB).
func (s *Store) Get() *DB {
	if d := s.p.Load(); d != nil {
		return d
	}
	return empty()
}

// Set replaces the snapshot.
func (s *Store) Set(d *DB) { s.p.Store(d) }

func empty() *DB {
	return &DB{desc: map[uint32]string{}, hosting: hostingASNs(), tor: map[netip.Addr]bool{}, crawlers: map[string][]netip.Prefix{}}
}

// Lookup classifies addr.
func (d *DB) Lookup(addr netip.Addr) Info {
	addr = addr.Unmap()
	info := Info{Class: "unknown"}
	if !addr.IsValid() {
		return info
	}
	tbl := d.v4
	if addr.Is6() {
		tbl = d.v6
	}
	i := sort.Search(len(tbl), func(i int) bool { return tbl[i].end.Compare(addr) >= 0 })
	if i < len(tbl) && tbl[i].start.Compare(addr) <= 0 && tbl[i].asn != 0 {
		info.ASN, info.Country = tbl[i].asn, tbl[i].cc
		info.Class = classify(info.ASN, d.desc[info.ASN], d.hosting)
	}
	info.Tor = d.tor[addr]
	for _, p := range d.drop {
		if p.Contains(addr) {
			info.Drop = true
			break
		}
	}
	for name, ps := range d.crawlers {
		for _, p := range ps {
			if p.Contains(addr) {
				info.Crawler = name
				break
			}
		}
	}
	return info
}

var (
	eduWords    = []string{"UNIVERSITY", "UNIV-", "-EDU", "EDU-", "COLLEGE", "ACADEMIC", "RESEARCH-NET", "NREN", "INSTITUTE OF TECHNOLOGY"}
	govWords    = []string{"GOVERNMENT", "MINISTRY", "-GOV", "GOV-", "NIC-IN"}
	mobileWords = []string{"MOBILE", "CELLULAR", "WIRELESS", "LTE", "JIO", "T-MOBILE", "VERIZON-WIRELESS"}
)

// containsWord matches w in u; words of four letters or fewer must stand
// alone (between non-alphanumerics), so "LTE" does not match "ALTERNET".
func containsWord(u, w string) bool {
	if len(w) > 4 {
		return strings.Contains(u, w)
	}
	alnum := func(c byte) bool { return c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' }
	for i := 0; ; {
		j := strings.Index(u[i:], w)
		if j < 0 {
			return false
		}
		j += i
		if (j == 0 || !alnum(u[j-1])) && (j+len(w) == len(u) || !alnum(u[j+len(w)])) {
			return true
		}
		i = j + 1
	}
}

func classify(asn uint32, desc string, hosting map[uint32]bool) string {
	if hosting[asn] {
		return "hosting"
	}
	u := strings.ToUpper(desc)
	for _, w := range eduWords {
		if containsWord(u, w) {
			return "edu"
		}
	}
	for _, w := range govWords {
		if containsWord(u, w) {
			return "gov"
		}
	}
	for _, w := range mobileWords {
		if containsWord(u, w) {
			return "mobile"
		}
	}
	return "isp"
}

//go:embed hosting_asns.txt
var hostingList string

func hostingASNs() map[uint32]bool {
	m := map[uint32]bool{}
	for _, line := range strings.Split(hostingList, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if n, err := strconv.ParseUint(f[0], 10, 32); err == nil {
			m[uint32(n)] = true
		}
	}
	return m
}

// File names inside the ipdata directory.
const (
	FileASN      = "ip2asn-combined.tsv.gz"
	FileTor      = "tor-exits.txt"
	FileDropV4   = "drop_v4.json"
	FileDropV6   = "drop_v6.json"
	FileCrawlers = "crawlers.json"
)

// Load reads whatever files exist in dir. Missing files are skipped and a
// file that fails to parse does not discard the others: the returned DB is
// always usable, and err (if any) describes what was skipped.
func Load(dir string) (*DB, error) {
	d := empty()
	d.Loaded = time.Now()
	var errs []error
	if f, err := os.Open(filepath.Join(dir, FileASN)); err == nil {
		asn := empty()
		err = asn.loadASN(f)
		f.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", FileASN, err))
		} else {
			d.v4, d.v6, d.desc = asn.v4, asn.v6, asn.desc
			d.Sources = append(d.Sources, "iptoasn.com (PDDL)")
		}
	}
	if tor := readTor(filepath.Join(dir, FileTor)); len(tor) > 0 {
		d.tor = tor
		d.Sources = append(d.Sources, "Tor Project exit list")
	}
	for _, fn := range []string{FileDropV4, FileDropV6} {
		d.drop = append(d.drop, readDrop(filepath.Join(dir, fn))...)
	}
	if len(d.drop) > 0 {
		d.Sources = append(d.Sources, "Spamhaus DROP")
	}
	if b, err := os.ReadFile(filepath.Join(dir, FileCrawlers)); err == nil {
		var m map[string][]string
		if err := json.Unmarshal(b, &m); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", FileCrawlers, err))
		} else {
			for name, list := range m {
				for _, s := range list {
					if p, err := netip.ParsePrefix(s); err == nil {
						d.crawlers[name] = append(d.crawlers[name], p.Masked())
					}
				}
			}
			d.Sources = append(d.Sources, "published crawler ranges")
		}
	}
	return d, errors.Join(errs...)
}

// readTor parses the exit list (one address per line).
func readTor(path string) map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(b), "\n") {
		if a, err := netip.ParseAddr(strings.TrimSpace(l)); err == nil {
			out[a.Unmap()] = true
		}
	}
	return out
}

// readDrop parses Spamhaus DROP (one JSON object per line).
func readDrop(path string) []netip.Prefix {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, l := range strings.Split(string(b), "\n") {
		var row struct {
			CIDR string `json:"cidr"`
		}
		if json.Unmarshal([]byte(l), &row) == nil && row.CIDR != "" {
			if p, err := netip.ParsePrefix(row.CIDR); err == nil {
				out = append(out, p.Masked())
			}
		}
	}
	return out
}

// loadASN parses iptoasn's TSV: start, end, asn, country, description.
func (d *DB) loadASN(r io.Reader) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()
	return d.parseASN(gz)
}

func (d *DB) parseASN(r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.SplitN(sc.Text(), "\t", 5)
		if len(f) < 4 {
			continue
		}
		start, err1 := netip.ParseAddr(f[0])
		end, err2 := netip.ParseAddr(f[1])
		asn, err3 := strconv.ParseUint(f[2], 10, 32)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		cc := strings.ToLower(f[3])
		if cc == "none" || len(cc) != 2 {
			cc = ""
		}
		r := rng{start: start.Unmap(), end: end.Unmap(), asn: uint32(asn), cc: cc}
		if r.start.Is4() {
			d.v4 = append(d.v4, r)
		} else {
			d.v6 = append(d.v6, r)
		}
		if len(f) == 5 && asn != 0 {
			if _, ok := d.desc[uint32(asn)]; !ok {
				d.desc[uint32(asn)] = f[4]
			}
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	for _, t := range [][]rng{d.v4, d.v6} {
		sort.Slice(t, func(i, j int) bool { return t[i].start.Less(t[j].start) })
	}
	if len(d.v4)+len(d.v6) == 0 {
		return errors.New("ipintel: no ranges parsed")
	}
	return nil
}

// Counts reports table sizes (for /readyz and the dashboard).
func (d *DB) Counts() map[string]int {
	return map[string]int{"v4": len(d.v4), "v6": len(d.v6), "tor": len(d.tor), "drop": len(d.drop), "hosting_asns": len(d.hosting)}
}
