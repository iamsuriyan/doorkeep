package velocity

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

// TestMemoryPerKey guards against the fixed-ring design that cost ~7 KB per
// key: 100k single-event keys must stay well under 100 MB.
func TestMemoryPerKey(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tr := New(func() time.Time { return now })
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	for i := 0; i < 100_000; i++ {
		tr.Add(fmt.Sprintf("ip:10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
	}
	runtime.GC()
	runtime.ReadMemStats(&b)
	perKey := float64(b.HeapAlloc-a.HeapAlloc) / 100_000
	t.Logf("%.0f bytes per single-event key", perKey)
	if perKey > 1000 {
		t.Fatalf("velocity tracker uses %.0f bytes per key", perKey)
	}
	now = now.Add(2 * time.Hour)
	tr.Sweep()
	if tr.Len() != 0 {
		t.Fatalf("sweep left %d idle keys", tr.Len())
	}
}
