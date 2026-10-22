package model

import (
	"math"
	"sync"

	"github.com/iamsuriyan/doorkeep/internal/scoring"
)

// Label weights.
const (
	WeightStrong = 1.0 // operator or site backend label
	WeightWeak   = 0.3 // inferred from challenge outcomes
)

// Promotion thresholds for the supervised model (design section 4.4).
const (
	MinLabels    = 200
	MinPerClass  = 50
	learningRate = 0.05
	l2           = 1e-4
)

// LogReg is an online L2-regularised logistic regression over one-hot
// (feature, bin) indicators. Safe for concurrent use.
type LogReg struct {
	mu       sync.Mutex
	W        map[string]float64 `json:"w"`
	Bias     float64            `json:"b"`
	Labels   int                `json:"n"`
	Bots     int                `json:"bots"`
	Humans   int                `json:"humans"`
	Promoted bool               `json:"promoted"`
	// Prequential evaluation: each label is scored before it trains.
	TP float64 `json:"tp"`
	FP float64 `json:"fp"`
	TN float64 `json:"tn"`
	FN float64 `json:"fn"`
}

// NewLogReg returns an empty model in shadow.
func NewLogReg() *LogReg { return &LogReg{W: map[string]float64{}} }

func indicators(f scoring.Features) []string {
	var out []string
	for _, d := range scoring.Registry() {
		if !d.Model {
			continue
		}
		if k, ok := keyOf(d, f); ok {
			out = append(out, d.Key()+"="+k)
		}
	}
	return out
}

func (m *LogReg) prob(xs []string) float64 {
	z := m.Bias
	for _, x := range xs {
		z += m.W[x]
	}
	return 1 / (1 + math.Exp(-z))
}

// Prob returns P(bot) for f.
func (m *LogReg) Prob(f scoring.Features) float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.prob(indicators(f))
}

// assess returns the label count, promotion state and P(bot) for f, read
// together under the lock (Learn and Promote write them concurrently).
func (m *LogReg) assess(f scoring.Features) (labels int, promoted bool, p float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Labels == 0 {
		return 0, m.Promoted, 0
	}
	return m.Labels, m.Promoted, m.prob(indicators(f))
}

// Learn updates with one labelled example (bot=true) and sample weight w.
func (m *LogReg) Learn(f scoring.Features, bot bool, w float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	xs := indicators(f)
	p := m.prob(xs)
	// Prequential: score before training.
	if w >= WeightStrong {
		switch {
		case p >= 0.5 && bot:
			m.TP++
		case p >= 0.5 && !bot:
			m.FP++
		case p < 0.5 && !bot:
			m.TN++
		default:
			m.FN++
		}
	}
	y := 0.0
	if bot {
		y = 1
	}
	g := (p - y) * w
	m.Bias -= learningRate * g
	for _, x := range xs {
		m.W[x] -= learningRate * (g + l2*m.W[x])
	}
	m.Labels++
	if bot {
		m.Bots++
	} else {
		m.Humans++
	}
}

// Ready reports whether the model has enough labels to be promoted.
func (m *LogReg) Ready() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Labels >= MinLabels && m.Bots >= MinPerClass && m.Humans >= MinPerClass
}

// Stats is the shadow report shown on the dashboard.
type Stats struct {
	Labels    int     `json:"labels"`
	Bots      int     `json:"bots"`
	Humans    int     `json:"humans"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	Ready     bool    `json:"ready"`
	Promoted  bool    `json:"promoted"`
}

// Report returns prequential precision/recall on strong labels.
func (m *LogReg) Report() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Stats{Labels: m.Labels, Bots: m.Bots, Humans: m.Humans, Promoted: m.Promoted}
	if m.TP+m.FP > 0 {
		s.Precision = m.TP / (m.TP + m.FP)
	}
	if m.TP+m.FN > 0 {
		s.Recall = m.TP / (m.TP + m.FN)
	}
	s.Ready = m.Labels >= MinLabels && m.Bots >= MinPerClass && m.Humans >= MinPerClass
	return s
}
