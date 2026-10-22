// Package model is the learned scoring layer (design section 4.4):
//
//   - HBOS, a histogram-based outlier score per site blended with a global
//     model, explainable per feature and updated online with exponential
//     decay (7-day half-life). It is trained only on traffic that was
//     allowed at low risk, so it models what normal visitors to this site
//     look like; training on all traffic would let a site under heavy bot
//     load learn bots as normal.
//   - An online logistic regression over the same features, trained from
//     operator labels and weak challenge labels. It is created in shadow and
//     reports prequential precision/recall until an operator promotes it.
//
// The model layer never overrides an allow-list and can never move an event
// from allow to block (enforced in scoring.Combine).
package model

import (
	"math"
	"sort"
	"sync"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/scoring"
)

// Tunables.
const (
	HalfLife        = 7 * 24 * time.Hour
	MinObservations = 200  // below this the model has no opinion
	BlendK          = 1000 // weight of the global model in site blending
	BlendFull       = 5000 // site observations after which global is ignored
	TrainMaxRisk    = 20   // only events allowed with risk below this train HBOS
	topContribs     = 3
)

// Contribution explains one feature's share of an anomaly score.
type Contribution struct {
	Feature string  `json:"feature"`
	Score   float64 `json:"score"` // -log p(bin)
}

// bin maps a numeric value to a histogram bin for its feature definition.
func bin(d scoring.Def, v float64) int {
	switch d.Kind {
	case scoring.KindBool:
		if v != 0 {
			return 1
		}
		return 0
	case scoring.KindBucket:
		return int(v)
	case scoring.KindFloat:
		if d.Max <= 1 && d.Min >= 0 {
			return int(math.Min(9, math.Floor(v*10)))
		}
		fallthrough
	default: // counts and wide floats: log2 bins
		if v < 0 {
			return 0
		}
		return int(math.Min(24, math.Floor(math.Log2(1+v))+1))
	}
}

// hist is a decayed histogram for one feature. Counts are stored in a
// growing time-weighted unit (weight e^{λt}) so decay costs nothing per
// update; probabilities are ratios and scale-invariant.
type hist struct {
	Bins  map[string]float64 `json:"b"` // bin key -> weighted count
	Total float64            `json:"t"`
}

// HBOS is safe for concurrent use.
type HBOS struct {
	mu   sync.Mutex
	Feat map[string]*hist `json:"f"`
	N    float64          `json:"n"`  // decayed observation count (in unit weight)
	Raw  int64            `json:"r"`  // raw observation count
	T0   int64            `json:"t0"` // unix seconds origin of the weight clock
	Dist *hist            `json:"s"`  // decayed distribution of past anomaly scores (for percentiles)
	now  func() time.Time
}

// NewHBOS returns an empty model.
func NewHBOS(now func() time.Time) *HBOS {
	if now == nil {
		now = time.Now
	}
	return &HBOS{Feat: map[string]*hist{}, T0: now().Unix(), Dist: &hist{Bins: map[string]float64{}}, now: now}
}

var lambda = math.Ln2 / HalfLife.Seconds()

func (h *HBOS) weight() float64 {
	dt := float64(h.now().Unix() - h.T0)
	w := math.Exp(lambda * dt)
	if w > 1e12 { // renormalise to keep floats in range
		h.rescale(1 / w)
		h.T0 = h.now().Unix()
		w = 1
	}
	return w
}

func (h *HBOS) rescale(f float64) {
	for _, x := range h.Feat {
		for k := range x.Bins {
			x.Bins[k] *= f
		}
		x.Total *= f
	}
	for k := range h.Dist.Bins {
		h.Dist.Bins[k] *= f
	}
	h.Dist.Total *= f
	h.N *= f
}

func keyOf(d scoring.Def, f scoring.Features) (string, bool) {
	if d.Kind == scoring.KindCat {
		v, ok := f.Cat[d.Key()]
		return "c:" + v, ok
	}
	v, ok := f.Num[d.Key()]
	if !ok || math.IsNaN(v) {
		return "", false
	}
	return string(rune('0' + bin(d, v))), true
}

// Observe adds one (normal) vector.
func (h *HBOS) Observe(f scoring.Features) {
	h.mu.Lock()
	defer h.mu.Unlock()
	w := h.weight()
	for _, d := range scoring.Registry() {
		if !d.Model {
			continue
		}
		k, ok := keyOf(d, f)
		if !ok {
			continue
		}
		x := h.Feat[d.Key()]
		if x == nil {
			x = &hist{Bins: map[string]float64{}}
			h.Feat[d.Key()] = x
		}
		x.Bins[k] += w
		x.Total += w
	}
	h.N += w
	h.Raw++
	// Record this vector's own score so percentiles track the population.
	s, _ := h.rawScore(f, nil)
	sk := string(rune('0' + int(math.Min(60, s/2))))
	h.Dist.Bins[sk] += w
	h.Dist.Total += w
}

// rawScore is Σ -log p(bin) over known features, with add-one smoothing.
// If global is given, probabilities are blended with it.
func (h *HBOS) rawScore(f scoring.Features, global *HBOS) (float64, []Contribution) {
	var total float64
	var cs []Contribution
	for _, d := range scoring.Registry() {
		if !d.Model {
			continue
		}
		k, ok := keyOf(d, f)
		if !ok {
			continue
		}
		p := h.prob(d.Key(), k)
		if global != nil && h.Raw < BlendFull {
			gp := global.probLocked(d.Key(), k)
			ns := float64(h.Raw)
			p = (ns*p + BlendK*gp) / (ns + BlendK)
		}
		s := -math.Log(p)
		total += s
		cs = append(cs, Contribution{Feature: d.Key(), Score: s})
	}
	return total, cs
}

func (h *HBOS) prob(feature, key string) float64 {
	x := h.Feat[feature]
	if x == nil || x.Total == 0 {
		return 0.5
	}
	// Add-one smoothing in unit-weight terms.
	unit := x.Total / math.Max(1, float64(h.Raw))
	return (x.Bins[key] + unit) / (x.Total + unit*float64(len(x.Bins)+1))
}

func (h *HBOS) probLocked(feature, key string) float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.prob(feature, key)
}

// Score returns a risk in 0..100 (0 = no opinion or typical) and the top
// contributing features. Risk is the score's position in the site's own
// distribution: below the 90th percentile is 0, the 99th percentile is 100.
func (h *HBOS) Score(f scoring.Features, global *HBOS) (int, []Contribution) {
	if global == h {
		global = nil // the global model scoring itself; locking it twice would deadlock
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.Raw < MinObservations {
		return 0, nil
	}
	s, cs := h.rawScore(f, global)
	pct := h.percentile(s)
	risk := 0.0
	if pct > 0.90 {
		risk = math.Min(100, (pct-0.90)/0.09*100)
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].Score > cs[j].Score })
	if len(cs) > topContribs {
		cs = cs[:topContribs]
	}
	return int(math.Round(risk)), cs
}

// percentile returns the share of past scores below s.
func (h *HBOS) percentile(s float64) float64 {
	if h.Dist.Total == 0 {
		return 0
	}
	b := int(math.Min(60, s/2))
	below := 0.0
	for k, v := range h.Dist.Bins {
		kb := int([]rune(k)[0] - '0')
		if kb < b {
			below += v
		} else if kb == b {
			below += v / 2
		}
	}
	return below / h.Dist.Total
}
