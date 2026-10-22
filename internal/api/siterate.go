package api

import (
	"context"
	"sync"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/scoring"
	"github.com/iamsuriyan/doorkeep/internal/store"
)

const (
	// baselineDays of hourly rollups form a site's normal rate for an hour
	// of the day; fewer than baselineMinDays of history means no opinion.
	baselineDays    = 7
	baselineMinDays = 3
	// A site is treated as under attack, raising proof-of-work difficulty,
	// when its last 10 minutes run at attackRatio times the baseline and
	// at least attackMinSubmits submits.
	attackRatio      = 5
	attackMinSubmits = 60
)

type baseline struct {
	hour   int64
	per10m float64
	ok     bool
}

// siteRates caches each site's baseline for the current hour.
type siteRates struct {
	mu sync.Mutex
	m  map[string]baseline
}

// baseline returns the site's average submits per 10 minutes for this hour
// of the day over the last week, from the hourly rollups.
func (s *Server) baseline(ctx context.Context, site *store.Site, now time.Time) (float64, bool) {
	hour := now.UTC().Truncate(time.Hour)
	s.rates.mu.Lock()
	if b, ok := s.rates.m[site.ID]; ok && b.hour == hour.Unix() {
		s.rates.mu.Unlock()
		return b.per10m, b.ok
	}
	s.rates.mu.Unlock()
	aggs, err := s.Store.Aggregates(ctx, site.ID, hour.Add(-baselineDays*24*time.Hour), hour)
	if err != nil {
		return 0, false
	}
	byHour := map[int64]float64{}
	for _, a := range aggs {
		if t, ok := a.Data["total"].(float64); ok {
			byHour[a.Hour.Unix()] = t
		} else if t, ok := a.Data["total"].(int); ok {
			byHour[a.Hour.Unix()] = float64(t)
		}
	}
	sum, days := 0.0, 0
	for k := 1; k <= baselineDays; k++ {
		h := hour.Add(-time.Duration(k) * 24 * time.Hour)
		if !site.CreatedAt.IsZero() && h.Before(site.CreatedAt.Truncate(time.Hour)) {
			break // the site did not exist yet; an empty hour is not "quiet"
		}
		sum += byHour[h.Unix()]
		days++
	}
	b := baseline{hour: hour.Unix(), ok: days >= baselineMinDays}
	if b.ok {
		b.per10m = sum / float64(days) / 6
	}
	s.rates.mu.Lock()
	if s.rates.m == nil {
		s.rates.m = map[string]baseline{}
	}
	s.rates.m[site.ID] = b
	s.rates.mu.Unlock()
	return b.per10m, b.ok
}

// applySiteRate sets vel.site_rate_ratio and reports whether the site is
// under an unusual surge (used to raise proof-of-work difficulty).
func (s *Server) applySiteRate(ctx context.Context, f scoring.Features, site *store.Site, now time.Time) (surge bool) {
	per10m, ok := s.baseline(ctx, site, now)
	if !ok {
		return false // too little history: neutral
	}
	recent := f.Get("vel.site_submits_10m")
	ratio := recent / max(per10m, 1)
	f.Set("vel.site_rate_ratio", ratio)
	return ratio >= attackRatio && recent >= attackMinSubmits
}
