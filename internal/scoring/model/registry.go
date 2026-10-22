package model

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/scoring"
)

// GlobalID is the model key shared across sites.
const GlobalID = "_global"

// Weights for blending model risk into the decision (design section 4.4).
const (
	WeightHBOS     = 0.3
	WeightPromoted = 0.5
)

// Registry holds per-site models plus the global HBOS.
type Registry struct {
	mu   sync.Mutex
	hbos map[string]*HBOS
	lr   map[string]*LogReg
	now  func() time.Time
}

// NewRegistry returns an empty registry.
func NewRegistry(now func() time.Time) *Registry {
	if now == nil {
		now = time.Now
	}
	return &Registry{hbos: map[string]*HBOS{}, lr: map[string]*LogReg{}, now: now}
}

func (r *Registry) h(site string) *HBOS {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.hbos[site]
	if m == nil {
		m = NewHBOS(r.now)
		r.hbos[site] = m
	}
	return m
}

// LR returns the site's supervised model.
func (r *Registry) LR(site string) *LogReg {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.lr[site]
	if m == nil {
		m = NewLogReg()
		r.lr[site] = m
	}
	return m
}

// Result of scoring one event.
type Result struct {
	Risk          int            // enforced model risk 0..100
	Weight        float64        // blend weight to apply
	Contributions []Contribution // top HBOS features
	ShadowLR      int            // LR risk while in shadow (-1 if not computed)
}

// Score evaluates the site's models for f. It does not train.
func (r *Registry) Score(site string, f scoring.Features) Result {
	res := Result{ShadowLR: -1}
	hr, cs := r.h(site).Score(f, r.h(GlobalID))
	res.Risk, res.Weight, res.Contributions = hr, WeightHBOS, cs
	if labels, promoted, prob := r.LR(site).assess(f); labels > 0 {
		p := int(prob * 100)
		if promoted {
			res.Risk, res.Weight = max(hr, p), WeightPromoted
		} else {
			res.ShadowLR = p
		}
	}
	return res
}

// ObserveAllowed trains HBOS on an event that was allowed at low risk.
func (r *Registry) ObserveAllowed(site string, f scoring.Features, risk int, outcome scoring.Outcome) {
	if outcome != scoring.Allow || risk >= TrainMaxRisk {
		return
	}
	r.h(site).Observe(f)
	r.h(GlobalID).Observe(f)
}

// Label trains the supervised model.
func (r *Registry) Label(site string, f scoring.Features, bot bool, weight float64) {
	r.LR(site).Learn(f, bot, weight)
}

// Promote toggles the supervised model for a site.
func (r *Registry) Promote(site string, on bool) bool {
	m := r.LR(site)
	m.mu.Lock()
	defer m.mu.Unlock()
	if on && !(m.Labels >= MinLabels && m.Bots >= MinPerClass && m.Humans >= MinPerClass) {
		return false
	}
	m.Promoted = on
	return true
}

// Status summarises a site's models for the dashboard.
type Status struct {
	HBOSObservations int64 `json:"hbos_observations"`
	HBOSActive       bool  `json:"hbos_active"`
	LR               Stats `json:"supervised"`
}

// Status returns the site's model status.
func (r *Registry) Status(site string) Status {
	h := r.h(site)
	h.mu.Lock()
	n := h.Raw
	h.mu.Unlock()
	return Status{HBOSObservations: n, HBOSActive: n >= MinObservations, LR: r.LR(site).Report()}
}

// Snapshot serialises every model, keyed by "hbos:<site>" / "lr:<site>".
func (r *Registry) Snapshot() map[string][]byte {
	r.mu.Lock()
	hs, ls := make(map[string]*HBOS, len(r.hbos)), make(map[string]*LogReg, len(r.lr))
	for k, v := range r.hbos {
		hs[k] = v
	}
	for k, v := range r.lr {
		ls[k] = v
	}
	r.mu.Unlock()
	out := map[string][]byte{}
	for k, v := range hs {
		v.mu.Lock()
		b, _ := json.Marshal(v)
		v.mu.Unlock()
		out["hbos:"+k] = b
	}
	for k, v := range ls {
		v.mu.Lock()
		b, _ := json.Marshal(v)
		v.mu.Unlock()
		out["lr:"+k] = b
	}
	return out
}

// Restore loads a snapshot produced by Snapshot.
func (r *Registry) Restore(snap map[string][]byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, b := range snap {
		switch {
		case len(k) > 5 && k[:5] == "hbos:":
			m := NewHBOS(r.now)
			if err := json.Unmarshal(b, m); err != nil {
				return err
			}
			if m.Dist == nil {
				m.Dist = &hist{Bins: map[string]float64{}}
			}
			r.hbos[k[5:]] = m
		case len(k) > 3 && k[:3] == "lr:":
			m := NewLogReg()
			if err := json.Unmarshal(b, m); err != nil {
				return err
			}
			r.lr[k[3:]] = m
		}
	}
	return nil
}
