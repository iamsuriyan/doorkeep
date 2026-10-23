package api

import (
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/pseudo"
	"github.com/iamsuriyan/doorkeep/internal/signals/ipintel"
)

// Opt-in blocklist sharing (config share_blocklist). Networks (/24 IPv4,
// /48 IPv6) that this instance blocked repeatedly in the last 24 hours are
// published at /v1/share/blocklist as a plain netset, which another
// doorkeep (or a firewall) can subscribe to with ipdata_blocklists.
//
// Counts live only in memory and only for 24 hours; nothing is written to
// disk. Only scored decisions count: blocks caused by the operator's own deny
// list are not shared, and nothing about visitors other than the network
// prefix is published.

const (
	shareWindowHours = 24
	shareMaxNets     = 200_000 // memory guard
)

type shareEntry struct {
	hours [shareWindowHours]uint32
	stamp [shareWindowHours]int64 // unix hour each slot belongs to
}

func (e *shareEntry) total(nowHour int64) uint32 {
	var n uint32
	for i, h := range e.stamp {
		if nowHour-h < shareWindowHours {
			n += e.hours[i]
		}
	}
	return n
}

type shareTracker struct {
	mu  sync.Mutex
	m   map[string]*shareEntry
	now func() time.Time
}

func newShareTracker(now func() time.Time) *shareTracker {
	return &shareTracker{m: map[string]*shareEntry{}, now: now}
}

// recordBlock counts one blocked submission from ip.
func (t *shareTracker) recordBlock(ip netip.Addr) {
	if t == nil || !ipintel.Listable(ip) {
		return
	}
	p := pseudo.Prefix(ip)
	hour := t.now().Unix() / 3600
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.m[p]
	if e == nil {
		if len(t.m) >= shareMaxNets {
			t.sweepLocked(hour)
			if len(t.m) >= shareMaxNets {
				return
			}
		}
		e = &shareEntry{}
		t.m[p] = e
	}
	i := hour % shareWindowHours
	if e.stamp[i] != hour {
		e.stamp[i], e.hours[i] = hour, 0
	}
	e.hours[i]++
}

func (t *shareTracker) sweepLocked(hour int64) {
	for p, e := range t.m {
		if e.total(hour) == 0 {
			delete(t.m, p)
		}
	}
}

// listed returns the networks with at least min blocks in the window.
func (t *shareTracker) listed(min int) []string {
	hour := t.now().Unix() / 3600
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweepLocked(hour)
	var out []string
	for p, e := range t.m {
		if int(e.total(hour)) >= min {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

func (s *Server) handleShareBlocklist(w http.ResponseWriter, r *http.Request) {
	if !s.Cfg.ShareBlocklist {
		http.NotFound(w, r)
		return
	}
	nets := s.share.listed(s.Cfg.ShareMinBlocks)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=900")
	fmt.Fprintf(w, "# doorkeep shared blocklist\n# Networks this instance blocked at least %d times in the last %d hours.\n# Generated %s. Entries: %d.\n",
		s.Cfg.ShareMinBlocks, shareWindowHours, s.Now().UTC().Format(time.RFC3339), len(nets))
	for _, p := range nets {
		fmt.Fprintln(w, p)
	}
}
