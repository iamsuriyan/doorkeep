package api

import (
	"context"
	"net/http"
	"sort"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/store"
)

// agg accumulates counts for one site-hour (or any window).
type agg struct {
	Outcomes  map[string]int `json:"outcomes"`
	Reasons   map[string]int `json:"reasons"`
	Countries map[string]int `json:"countries"`
	ASNClass  map[string]int `json:"asn_class"`
	Browsers  map[string]int `json:"browsers"`
	RiskHist  [20]int        `json:"risk_hist"`
	Challenge map[string]int `json:"challenge"` // pow_ok, visual_ok, visual_fail
	Verified  int            `json:"verified"`
	Labels    map[string]int `json:"labels"`
	Total     int            `json:"total"`
}

func newAgg() *agg {
	return &agg{Outcomes: map[string]int{}, Reasons: map[string]int{}, Countries: map[string]int{}, ASNClass: map[string]int{},
		Browsers: map[string]int{}, Challenge: map[string]int{}, Labels: map[string]int{}}
}

func (a *agg) add(e *store.Event) {
	a.Total++
	a.Outcomes[string(e.Outcome)]++
	for _, r := range e.Reasons {
		if r.Weight != 0 || len(r.Code) > 8 && r.Code[:8] == "PROFILE_" {
			a.Reasons[r.Code]++
		}
	}
	if e.Country != "" {
		a.Countries[e.Country]++
	}
	if e.ASNClass != "" {
		a.ASNClass[e.ASNClass]++
	}
	if e.UAFamily != "" {
		a.Browsers[e.UAFamily]++
	}
	a.RiskHist[min(19, e.Risk/5)]++
	if e.ChallengeOK != nil {
		k := e.ChallengeKind + "_fail"
		if *e.ChallengeOK {
			k = e.ChallengeKind + "_ok"
		}
		a.Challenge[k]++
	}
	if e.VerifiedAt != nil {
		a.Verified++
	}
	if e.Label != "" {
		a.Labels[e.Label]++
	}
}

func (a *agg) merge(b *agg) {
	a.Total += b.Total
	a.Verified += b.Verified
	for i := range a.RiskHist {
		a.RiskHist[i] += b.RiskHist[i]
	}
	for _, p := range [][2]map[string]int{{a.Outcomes, b.Outcomes}, {a.Reasons, b.Reasons}, {a.Countries, b.Countries}, {a.ASNClass, b.ASNClass}, {a.Browsers, b.Browsers}, {a.Challenge, b.Challenge}, {a.Labels, b.Labels}} {
		for k, v := range p[1] {
			p[0][k] += v
		}
	}
}

func (a *agg) toMap() map[string]any {
	return map[string]any{"outcomes": a.Outcomes, "reasons": a.Reasons, "countries": a.Countries, "asn_class": a.ASNClass,
		"browsers": a.Browsers, "risk_hist": a.RiskHist, "challenge": a.Challenge, "verified": a.Verified, "labels": a.Labels, "total": a.Total}
}

func aggFromMap(m map[string]any) *agg {
	a := newAgg()
	num := func(v any) int { f, _ := v.(float64); return int(f) }
	fill := func(dst map[string]int, v any) {
		if mm, ok := v.(map[string]any); ok {
			for k, x := range mm {
				dst[k] = num(x)
			}
		}
	}
	fill(a.Outcomes, m["outcomes"])
	fill(a.Reasons, m["reasons"])
	fill(a.Countries, m["countries"])
	fill(a.ASNClass, m["asn_class"])
	fill(a.Browsers, m["browsers"])
	fill(a.Challenge, m["challenge"])
	fill(a.Labels, m["labels"])
	if h, ok := m["risk_hist"].([]any); ok {
		for i := 0; i < len(h) && i < 20; i++ {
			a.RiskHist[i] = num(h[i])
		}
	}
	a.Verified, a.Total = num(m["verified"]), num(m["total"])
	return a
}

// Rollup aggregates the given completed hours for every site. Idempotent;
// the janitor re-runs it over recent hours so late labels and
// verifications are reflected.
func (s *Server) Rollup(ctx context.Context, hours int) error {
	sites, err := s.Store.ListSites(ctx)
	if err != nil {
		return err
	}
	end := s.Now().UTC().Truncate(time.Hour)
	for _, site := range sites {
		for h := 1; h <= hours; h++ {
			start := end.Add(-time.Duration(h) * time.Hour)
			a := newAgg()
			err := s.Store.StreamEvents(ctx, store.EventFilter{SiteID: site.ID, Since: start, Until: start.Add(time.Hour)}, func(e *store.Event) error {
				a.add(e)
				return nil
			})
			if err != nil {
				return err
			}
			if a.Total == 0 {
				continue
			}
			if err := s.Store.PutAggregate(ctx, site.ID, store.Aggregate{Hour: start, Data: a.toMap()}); err != nil {
				return err
			}
		}
	}
	return nil
}

type kv struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

func top(m map[string]int, n int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// adminStats returns an hourly series plus breakdowns for a range (default
// 24h, up to 90 days). Completed hours come from aggregates; the current
// hour is computed live.
func (s *Server) adminStats(w http.ResponseWriter, r *http.Request) {
	site := s.site(w, r)
	if site == nil {
		return
	}
	rng, err := time.ParseDuration(r.URL.Query().Get("range"))
	if err != nil || rng <= 0 {
		rng = 24 * time.Hour
	}
	rng = min(rng, 90*24*time.Hour)
	now := s.Now().UTC()
	cur := now.Truncate(time.Hour)
	since := cur.Add(-rng + time.Hour)
	hours := map[int64]*agg{}
	aggs, err := s.Store.Aggregates(r.Context(), site.ID, since, cur)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	for _, a := range aggs {
		hours[a.Hour.Unix()] = aggFromMap(a.Data)
	}
	// Hours not yet rolled up (e.g. right after startup) and the current hour.
	err = s.Store.StreamEvents(r.Context(), store.EventFilter{SiteID: site.ID, Since: since}, func(e *store.Event) error {
		h := e.TS.UTC().Truncate(time.Hour).Unix()
		if _, rolled := hours[h]; rolled && h != cur.Unix() {
			return nil
		}
		a := hours[h]
		if a == nil || (h == cur.Unix() && a == nil) {
			a = newAgg()
			hours[h] = a
		}
		a.add(e)
		return nil
	})
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	total := newAgg()
	type point struct {
		Hour      time.Time `json:"hour"`
		Allow     int       `json:"allow"`
		Challenge int       `json:"challenge"`
		Block     int       `json:"block"`
	}
	var series []point
	for t := since; !t.After(cur); t = t.Add(time.Hour) {
		p := point{Hour: t}
		if a := hours[t.Unix()]; a != nil {
			p.Allow, p.Challenge, p.Block = a.Outcomes["allow"], a.Outcomes["challenge"], a.Outcomes["block"]
			total.merge(a)
		}
		series = append(series, p)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"range": rng.String(), "series": series, "totals": total.Outcomes, "total": total.Total, "verified": total.Verified,
		"reasons": top(total.Reasons, 15), "countries": top(total.Countries, 10), "asn_class": top(total.ASNClass, 6),
		"browsers": top(total.Browsers, 8), "risk_hist": total.RiskHist, "challenge": total.Challenge, "labels": total.Labels,
	})
}
