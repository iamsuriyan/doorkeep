package api

import (
	"testing"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/scoring"
	"github.com/iamsuriyan/doorkeep/internal/store"
)

func TestSiteRateRatioAndSurge(t *testing.T) {
	h := newHarness(t)
	h.clock = time.Date(2026, 10, 22, 14, 30, 0, 0, time.UTC)
	site, _ := h.srv.Store.SiteByID(t.Context(), "site1")
	// A site created two days ago: no opinion yet.
	site.CreatedAt = h.clock.Add(-50 * time.Hour)
	for k := 1; k <= 2; k++ {
		hour := h.clock.Truncate(time.Hour).Add(-time.Duration(k) * 24 * time.Hour)
		h.srv.Store.PutAggregate(t.Context(), site.ID, store.Aggregate{Hour: hour, Data: map[string]any{"total": 60}})
	}
	f := scoring.NewFeatures()
	f.Set("vel.site_submits_10m", 100)
	if h.srv.applySiteRate(t.Context(), f, site, h.clock) || f.Has("vel.site_rate_ratio") {
		t.Fatal("ratio set with under three days of history")
	}

	// A week at 60 submits in this hour: 10 per 10 minutes.
	site.CreatedAt = h.clock.Add(-30 * 24 * time.Hour)
	h.clock = h.clock.Add(time.Hour) // new hour: the cached baseline is recomputed
	for k := 1; k <= 7; k++ {
		hour := h.clock.Truncate(time.Hour).Add(-time.Duration(k) * 24 * time.Hour)
		h.srv.Store.PutAggregate(t.Context(), site.ID, store.Aggregate{Hour: hour, Data: map[string]any{"total": 60}})
	}
	f = scoring.NewFeatures()
	f.Set("vel.site_submits_10m", 12)
	if h.srv.applySiteRate(t.Context(), f, site, h.clock) {
		t.Fatal("normal traffic treated as a surge")
	}
	if r := f.Get("vel.site_rate_ratio"); r < 1.1 || r > 1.3 {
		t.Fatalf("ratio %v, want 1.2", r)
	}
	f = scoring.NewFeatures()
	f.Set("vel.site_submits_10m", 100)
	if !h.srv.applySiteRate(t.Context(), f, site, h.clock) {
		t.Fatalf("10x traffic not a surge (ratio %v)", f.Get("vel.site_rate_ratio"))
	}
}
