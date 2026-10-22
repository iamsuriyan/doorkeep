package velocity

import (
	"fmt"
	"os"
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
