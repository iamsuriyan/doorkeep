package ipintel

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Blocklist is a third-party IP reputation list in plain text: one address
// or CIDR per line, "#" or ";" comments. FireHOL netsets, CrowdSec
// blocklist integrations, Spamhaus-style lists and another doorkeep's
// shared feed (/v1/share/blocklist) all use this format. Credentials, where
// a list needs them, go in the URL (https://user:pass@host/...).
type Blocklist struct {
	Name string `yaml:"name" json:"name"`
	URL  string `yaml:"url" json:"url"`
}

// DefaultBlocklists are fetched unless configured otherwise. FireHOL level 1
// combines lists maintained to have no false positives (Spamhaus DROP and
// EDROP, DShield top attackers, Feodo and similar botnet trackers).
var DefaultBlocklists = []Blocklist{
	{Name: "firehol_level1", URL: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"},
}

var blocklistName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)

// ValidBlocklistName reports whether name can be used as a list's file name.
func ValidBlocklistName(name string) bool { return blocklistName.MatchString(name) }

func blocklistFile(name string) string { return "list-" + name + ".txt" }

// notGlobal holds ranges that never belong on an abuse list: private,
// shared (CGNAT), loopback, link-local, documentation, benchmarking,
// multicast and reserved. FireHOL level 1 includes them as "bogons", which
// is right for a border firewall but wrong here: doorkeep behind a reverse
// proxy or on an intranet sees exactly these addresses.
var notGlobal = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/3",
		"::/8", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32", "64:ff9b::/96",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// Listable reports whether addr may appear on a blocklist: global unicast
// and outside the private, shared and documentation ranges.
func Listable(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsValid() && usable(netip.PrefixFrom(addr, addr.BitLen()))
}

// ParseBlocklist reads a plain-text list (see Blocklist), keeping the
// ranges usable for blocking.
func ParseBlocklist(r io.Reader) []netip.Prefix { return parseBlocklist(r) }

// usable reports whether p may be used for blocking: global unicast and not
// absurdly broad (a /8 or wider IPv4 range, /16 or wider IPv6, is a
// mistake in a list, not a target).
func usable(p netip.Prefix) bool {
	if (p.Addr().Is4() && p.Bits() < 9) || (p.Addr().Is6() && p.Bits() < 17) {
		return false
	}
	for _, n := range notGlobal {
		if n.Overlaps(p) {
			return false
		}
	}
	return true
}

// parseBlocklist reads a plain-text list, keeping usable prefixes.
func parseBlocklist(r io.Reader) []netip.Prefix {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		var p netip.Prefix
		if strings.Contains(f[0], "/") {
			pp, err := netip.ParsePrefix(f[0])
			if err != nil {
				continue
			}
			p = pp.Masked()
		} else {
			a, err := netip.ParseAddr(f[0])
			if err != nil {
				continue
			}
			a = a.Unmap()
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if usable(p) {
			out = append(out, p)
		}
	}
	return out
}

func readBlocklist(path string) []netip.Prefix {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseBlocklist(f)
}

func validBlocklist(path string) error {
	if len(readBlocklist(path)) == 0 {
		return errors.New("no usable addresses in list")
	}
	return nil
}

// span is an inclusive address range tagged with the list it came from.
type span struct {
	lo, hi netip.Addr
	list   string
}

// rangeSet answers "which list contains addr" in O(log n). Overlapping
// ranges are merged, across lists too, so every address falls in at most
// one span; a merged span keeps the name of the list that starts it.
type rangeSet struct {
	v4, v6 []span
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().As16()
	bits := p.Bits()
	if p.Addr().Is4() {
		bits += 96
	}
	for i := bits; i < 128; i++ {
		a[i/8] |= 1 << (7 - i%8)
	}
	out := netip.AddrFrom16(a)
	if p.Addr().Is4() {
		return out.Unmap()
	}
	return out
}

func (s *rangeSet) add(list string, ps []netip.Prefix) {
	for _, p := range ps {
		sp := span{lo: p.Addr(), hi: lastAddr(p), list: list}
		if sp.lo.Is4() {
			s.v4 = append(s.v4, sp)
		} else {
			s.v6 = append(s.v6, sp)
		}
	}
}

// finish sorts by start and merges overlapping or adjacent ranges.
func (s *rangeSet) finish() {
	for _, t := range []*[]span{&s.v4, &s.v6} {
		slices.SortFunc(*t, func(a, b span) int {
			if c := a.lo.Compare(b.lo); c != 0 {
				return c
			}
			return strings.Compare(a.list, b.list)
		})
		var out []span
		for _, sp := range *t {
			if n := len(out); n > 0 && (!out[n-1].hi.Next().IsValid() || sp.lo.Compare(out[n-1].hi.Next()) <= 0) {
				if sp.hi.Compare(out[n-1].hi) > 0 {
					out[n-1].hi = sp.hi
				}
				continue
			}
			out = append(out, sp)
		}
		*t = out
	}
}

// lookup returns the name of a list containing addr, or "".
func (s *rangeSet) lookup(addr netip.Addr) string {
	t := s.v4
	if addr.Is6() {
		t = s.v6
	}
	// The last span starting at or before addr is the only candidate.
	i := sort.Search(len(t), func(i int) bool { return t[i].lo.Compare(addr) > 0 })
	if i > 0 && t[i-1].hi.Compare(addr) >= 0 {
		return t[i-1].list
	}
	return ""
}

func (s *rangeSet) len() int { return len(s.v4) + len(s.v6) }

// loadBlocklists reads the configured lists from dir.
func loadBlocklists(dir string, names []string) (*rangeSet, []string, error) {
	rs := &rangeSet{}
	var loaded []string
	var errs []error
	for _, n := range names {
		if !ValidBlocklistName(n) {
			errs = append(errs, fmt.Errorf("blocklist %q: invalid name", n))
			continue
		}
		ps := readBlocklist(filepath.Join(dir, blocklistFile(n)))
		if len(ps) == 0 {
			continue // not downloaded yet
		}
		rs.add(n, ps)
		loaded = append(loaded, n)
	}
	rs.finish()
	return rs, loaded, errors.Join(errs...)
}
