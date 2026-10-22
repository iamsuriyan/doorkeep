package velocity

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// TestRedisMatchesTracker runs the same sequence through both
// implementations (requires DK_TEST_REDIS, e.g. redis://127.0.0.1:16379/0).
func TestRedisMatchesTracker(t *testing.T) {
	url := os.Getenv("DK_TEST_REDIS")
	if url == "" {
		t.Skip("set DK_TEST_REDIS")
	}
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	r, err := NewRedis(url, clock, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.prefix = fmt.Sprintf("dktest%d:", time.Now().UnixNano())
	mem := New(clock)
	for i := 0; i < 12; i++ {
		for _, c := range []Counter{r, mem} {
			c.Add("fp:x", fmt.Sprintf("asn:%d", i%5), "24:same")
		}
		now = now.Add(20 * time.Second)
	}
	for _, d := range []time.Duration{time.Minute, 10 * time.Minute, time.Hour} {
		if a, b := r.Count("fp:x", d), mem.Count("fp:x", d); a != b {
			t.Errorf("count %s: redis %d memory %d", d, a, b)
		}
		if a, b := r.Distinct("fp:x", d, "asn:"), mem.Distinct("fp:x", d, "asn:"); a != b {
			t.Errorf("distinct %s: redis %d memory %d", d, a, b)
		}
	}
	if a, b := r.IntervalCV("fp:x"), mem.IntervalCV("fp:x"); fmt.Sprintf("%.4f", a) != fmt.Sprintf("%.4f", b) {
		t.Errorf("cv: redis %f memory %f", a, b)
	}
}

// TestRedisFallsBackToLocal checks that an unreachable Redis degrades to
// this node's own counts instead of reading zero (which would switch off
// session rate limits).
func TestRedisFallsBackToLocal(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	// Nothing listens on port 1; NewRedis's ping fails but the client is usable.
	r, _ := NewRedis("redis://127.0.0.1:1/0", clock, nil)
	defer r.Close()
	for range 7 {
		r.Add("sess-ip:x", "asn:1")
	}
	if c := r.Count("sess-ip:x", time.Minute); c != 7 {
		t.Fatalf("fallback count %d, want 7", c)
	}
	if d := r.Distinct("sess-ip:x", time.Hour, "asn:"); d != 1 {
		t.Fatalf("fallback distinct %d, want 1", d)
	}
}

// TestWindowKeysCoverWindow checks the minute/bucket key decomposition.
func TestWindowKeysCoverWindow(t *testing.T) {
	for _, off := range []time.Duration{0, 10 * time.Second, 30 * time.Second, 50 * time.Second} {
		now := time.Unix(1_800_000_000, 0).Add(off)
		r := &Redis{prefix: "p:", now: func() time.Time { return now }}
		for _, d := range []time.Duration{time.Minute, 10 * time.Minute, time.Hour} {
			covered := int64(0)
			for _, k := range r.windowKeys("c", "k", "", d) {
				if strings.Contains(k, ":m") {
					covered += bucketsPerMin
				} else {
					covered++
				}
			}
			if covered != int64(d/bucket) {
				t.Fatalf("offset %s window %s covers %d buckets", off, d, covered)
			}
			if d == time.Hour && len(r.windowKeys("c", "k", "", d)) > 70 {
				t.Fatalf("hour window uses %d keys", len(r.windowKeys("c", "k", "", d)))
			}
		}
	}
}
