package velocity

import (
	"fmt"
	"math"
	"testing"
	"time"
)

func TestWindowsExpire(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tr := New(func() time.Time { return now })
	for i := 0; i < 5; i++ {
		tr.Add("ip:a")
	}
	if c := tr.Count("ip:a", time.Minute); c != 5 {
		t.Fatalf("count %d", c)
	}
	now = now.Add(2 * time.Minute)
	tr.Add("ip:a")
	if c := tr.Count("ip:a", time.Minute); c != 1 {
		t.Fatalf("1m window should hold only the new event, got %d", c)
	}
	if c := tr.Count("ip:a", 10*time.Minute); c != 6 {
		t.Fatalf("10m window %d", c)
	}
	now = now.Add(2 * time.Hour)
	if c := tr.Count("ip:a", time.Hour); c != 0 {
		t.Fatalf("stale ring slots counted: %d", c)
	}
}

func TestDistinctMembers(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tr := New(func() time.Time { return now })
	for i := 0; i < 7; i++ {
		tr.Add("fp:x", fmt.Sprintf("asn:%d", 100+i%5), "ip24:same")
		now = now.Add(time.Minute)
	}
	if d := tr.Distinct("fp:x", time.Hour, "asn:"); d != 5 {
		t.Fatalf("distinct asn %d", d)
	}
	if d := tr.Distinct("fp:x", time.Hour, "ip24:"); d != 1 {
		t.Fatalf("distinct ip24 %d", d)
	}
}

func TestIntervalCV(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tr := New(func() time.Time { return now })
	if !math.IsNaN(tr.IntervalCV("k")) {
		t.Fatal("expected NaN with no data")
	}
	for i := 0; i < 12; i++ {
		tr.Add("k")
		now = now.Add(30 * time.Second)
	}
	if cv := tr.IntervalCV("k"); cv > 0.001 {
		t.Fatalf("metronome cadence cv %f", cv)
	}
}
