// Package velocity keeps in-process sliding-window counters per IP, /24,
// fingerprint, canvas hash and site (design section 3.5). Keys are
// pseudonymous hashes; nothing here is persisted. A cluster deployment
// swaps this for the Redis implementation behind the same interface.
package velocity

import (
	"math"
	"sync"
	"time"
)

// Windows reported by Snapshot.
var Windows = []struct {
	Name string
	Dur  time.Duration
}{{"1m", time.Minute}, {"10m", 10 * time.Minute}, {"1h", time.Hour}}

const (
	bucket   = 10 * time.Second
	nBuckets = int(time.Hour / bucket) // 360 buckets cover the longest window
	maxKeys  = 200_000                 // memory guard; oldest keys evicted first
)

// series is a ring of per-bucket counts plus, optionally, per-bucket sets of
// distinct members (for "distinct ASNs per fingerprint").
type series struct {
	counts  [nBuckets]uint32
	members [nBuckets]map[string]struct{}
	epoch   [nBuckets]int64 // bucket index each slot currently holds
	last    int64
	times   []int64 // recent event times (ms) for cadence, capped
}

// Tracker is safe for concurrent use.
type Tracker struct {
	mu  sync.Mutex
	m   map[string]*series
	now func() time.Time
}

// New returns a tracker.
func New(now func() time.Time) *Tracker {
	if now == nil {
		now = time.Now
	}
	return &Tracker{m: map[string]*series{}, now: now}
}

func (t *Tracker) get(key string) *series {
	s := t.m[key]
	if s == nil {
		if len(t.m) >= maxKeys {
			t.evict()
		}
		s = &series{}
		t.m[key] = s
	}
	return s
}

// evict drops keys idle for more than an hour, then arbitrary keys if still full.
func (t *Tracker) evict() {
	cutoff := t.now().Add(-time.Hour).UnixNano() / int64(bucket)
	for k, s := range t.m {
		if s.last < cutoff {
			delete(t.m, k)
		}
	}
	for k := range t.m {
		if len(t.m) < maxKeys*9/10 {
			break
		}
		delete(t.m, k)
	}
}

// Add records one event for key, optionally with a member value whose
// distinct count is tracked (e.g. key=fp:<hash>, member=asn:<n>).
func (t *Tracker) Add(key string, members ...string) {
	now := t.now()
	idx := now.UnixNano() / int64(bucket)
	slot := int(idx % int64(nBuckets))
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.get(key)
	if s.epoch[slot] != idx {
		s.epoch[slot] = idx
		s.counts[slot] = 0
		s.members[slot] = nil
	}
	s.counts[slot]++
	for _, m := range members {
		if m == "" {
			continue
		}
		if s.members[slot] == nil {
			s.members[slot] = map[string]struct{}{}
		}
		if len(s.members[slot]) < 1024 {
			s.members[slot][m] = struct{}{}
		}
	}
	s.last = idx
	s.times = append(s.times, now.UnixMilli())
	if len(s.times) > 32 {
		s.times = s.times[len(s.times)-32:]
	}
}

// Count returns events for key within d.
func (t *Tracker) Count(key string, d time.Duration) int {
	n, _ := t.stats(key, d, "")
	return n
}

// Distinct returns the number of distinct members with the given prefix seen
// for key within d.
func (t *Tracker) Distinct(key string, d time.Duration, prefix string) int {
	_, m := t.stats(key, d, prefix)
	return m
}

func (t *Tracker) stats(key string, d time.Duration, prefix string) (int, int) {
	now := t.now()
	idx := now.UnixNano() / int64(bucket)
	span := int64(d / bucket)
	if span < 1 {
		span = 1
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.m[key]
	if s == nil {
		return 0, 0
	}
	total := 0
	var set map[string]struct{}
	if prefix != "" {
		set = map[string]struct{}{}
	}
	for i := int64(0); i < span && i < int64(nBuckets); i++ {
		b := idx - i
		slot := int(((b % int64(nBuckets)) + int64(nBuckets)) % int64(nBuckets))
		if s.epoch[slot] != b {
			continue
		}
		total += int(s.counts[slot])
		if set != nil {
			for m := range s.members[slot] {
				if len(m) >= len(prefix) && m[:len(prefix)] == prefix {
					set[m] = struct{}{}
				}
			}
		}
	}
	return total, len(set)
}

// IntervalCV returns the coefficient of variation of the last inter-event
// intervals for key, or NaN with fewer than 10 events.
func (t *Tracker) IntervalCV(key string) float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.m[key]
	if s == nil || len(s.times) < 10 {
		return math.NaN()
	}
	var n, mean, m2 float64
	for i := 1; i < len(s.times); i++ {
		x := float64(s.times[i] - s.times[i-1])
		n++
		d := x - mean
		mean += d / n
		m2 += d * (x - mean)
	}
	if mean == 0 || n < 2 {
		return 0
	}
	return math.Sqrt(m2/(n-1)) / mean
}

// Len returns the number of tracked keys (for metrics).
func (t *Tracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}

// Counter is implemented by Tracker (in-process) and Redis (shared across
// cluster nodes).
type Counter interface {
	Add(key string, members ...string)
	Count(key string, d time.Duration) int
	Distinct(key string, d time.Duration, prefix string) int
	IntervalCV(key string) float64
	Len() int
}

var _ Counter = (*Tracker)(nil)
