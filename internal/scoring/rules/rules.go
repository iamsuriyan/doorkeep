// Package rules is the transparent scoring layer: weighted rules written as
// expr expressions over the feature vector, allow/deny/challenge lists, and
// per-site thresholds. Every fired rule contributes a reason code; rules in
// shadow mode are evaluated and recorded but never change the risk
// (design section 4.3 and 4.6).
package rules

import (
	_ "embed"
	"fmt"
	"math"
	"regexp"
	"sort"

	"github.com/iamsuriyan/doorkeep/internal/scoring"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"go.yaml.in/yaml/v3"
)

// Mode controls whether a rule affects the decision.
type Mode string

const (
	ModeEnforce Mode = "enforce"
	ModeShadow  Mode = "shadow"
	ModeOff     Mode = "off"
)

// Rule is one weighted rule.
type Rule struct {
	ID            string `yaml:"id" json:"id"`
	When          string `yaml:"when" json:"when"`
	Unless        string `yaml:"unless,omitempty" json:"unless,omitempty"`
	Weight        int    `yaml:"weight" json:"weight"`
	Mode          Mode   `yaml:"mode,omitempty" json:"mode,omitempty"`
	Informational bool   `yaml:"informational,omitempty" json:"informational,omitempty"`
	Description   string `yaml:"description,omitempty" json:"description,omitempty"`

	when   *vm.Program
	unless *vm.Program
}

// Set is a compiled, immutable rule set.
type Set struct {
	Version string
	rules   []*Rule
}

//go:embed builtin.yaml
var builtinYAML []byte

// Builtin returns the compiled built-in rule set.
func Builtin() (*Set, error) { return Parse(builtinYAML, "builtin") }

// Parse compiles a YAML rule list. Expressions are compiled once against a
// generic environment; unknown identifiers are errors so typos fail loudly.
func Parse(src []byte, version string) (*Set, error) {
	var rs []*Rule
	if err := yaml.Unmarshal(src, &rs); err != nil {
		return nil, fmt.Errorf("rules: yaml: %w", err)
	}
	return Compile(rs, version)
}

// Compile validates and compiles rules.
func Compile(rs []*Rule, version string) (*Set, error) {
	seen := map[string]bool{}
	env := sampleEnv()
	for _, r := range rs {
		if r.ID == "" || r.When == "" {
			return nil, fmt.Errorf("rules: rule missing id or when")
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("rules: duplicate id %s", r.ID)
		}
		seen[r.ID] = true
		if r.Mode == "" {
			r.Mode = ModeEnforce
		}
		if r.Weight < -100 || r.Weight > 100 {
			return nil, fmt.Errorf("rules: %s weight out of range", r.ID)
		}
		if err := checkFeatureRefs(r.When + " " + r.Unless); err != nil {
			return nil, fmt.Errorf("rules: %s: %w", r.ID, err)
		}
		var err error
		if r.when, err = expr.Compile(r.When, expr.Env(env), expr.AsBool()); err != nil {
			return nil, fmt.Errorf("rules: %s when: %w", r.ID, err)
		}
		if r.Unless != "" {
			if r.unless, err = expr.Compile(r.Unless, expr.Env(env), expr.AsBool()); err != nil {
				return nil, fmt.Errorf("rules: %s unless: %w", r.ID, err)
			}
		}
	}
	return &Set{Version: version, rules: rs}, nil
}

// Rules returns a copy of the rule definitions.
func (s *Set) Rules() []Rule {
	out := make([]Rule, len(s.rules))
	for i, r := range s.rules {
		out[i] = *r
	}
	return out
}

// Hit is one fired rule.
type Hit struct {
	ID     string `json:"id"`
	Weight int    `json:"w"`
	Shadow bool   `json:"shadow,omitempty"`
}

// Result of evaluating a set.
type Result struct {
	Risk       int   // clamp(sum enforced weights, 0, 100)
	ShadowRisk int   // what risk would be if shadow rules were enforced
	Hits       []Hit // enforced + informational hits, sorted by |weight| desc
	Shadow     []Hit // shadow hits
}

// Eval runs every rule against env. Evaluation errors (for example a NaN in
// a comparison that expr rejects) make that rule not fire; they never fire a
// rule by accident.
func (s *Set) Eval(env map[string]any) Result {
	var res Result
	sum, shadowSum := 0, 0
	for _, r := range s.rules {
		if r.Mode == ModeOff {
			continue
		}
		if !run(r.when, env) {
			continue
		}
		if r.unless != nil && run(r.unless, env) {
			continue
		}
		h := Hit{ID: r.ID, Weight: r.Weight}
		if r.Mode == ModeShadow {
			h.Shadow = true
			res.Shadow = append(res.Shadow, h)
			shadowSum += r.Weight
			continue
		}
		res.Hits = append(res.Hits, h)
		sum += r.Weight
		shadowSum += r.Weight
	}
	res.Risk = clamp(sum)
	res.ShadowRisk = clamp(shadowSum)
	sortHits(res.Hits)
	sortHits(res.Shadow)
	return res
}

func run(p *vm.Program, env map[string]any) bool {
	out, err := expr.Run(p, env)
	if err != nil {
		return false
	}
	b, ok := out.(bool)
	return ok && b
}

func clamp(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func sortHits(h []Hit) {
	sort.SliceStable(h, func(i, j int) bool {
		return abs(h[i].Weight) > abs(h[j].Weight)
	})
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// sampleEnv is the typed shape rules compile against: every feature group as
// map[string]any plus request context. Values are placeholders.
func sampleEnv() map[string]any {
	return map[string]any{
		"prof":   map[string]any{},
		"auto":   map[string]any{},
		"fp":     map[string]any{},
		"beh":    map[string]any{},
		"env":    map[string]any{},
		"t":      map[string]any{},
		"net":    map[string]any{},
		"vel":    map[string]any{},
		"action": "",
		"site":   map[string]any{},
		"isNaN":  math.IsNaN,
		"known":  func(v any) bool { f, ok := v.(float64); return !ok || !math.IsNaN(f) },
	}
}

// Context adds request-level values to a feature env.
func Context(env map[string]any, action string, interactiveActions []string) map[string]any {
	env["action"] = action
	env["site"] = map[string]any{"interactive_actions": interactiveActions}
	env["isNaN"] = math.IsNaN
	env["known"] = func(v any) bool { f, ok := v.(float64); return !ok || !math.IsNaN(f) }
	return env
}

var featureRef = regexp.MustCompile(`\b(prof|auto|fp|beh|env|t|net|vel)\.([a-z0-9_]+)\b`)

// checkFeatureRefs rejects references to feature keys that are not in the
// registry, so a typo cannot produce a rule that silently never fires.
func checkFeatureRefs(src string) error {
	for _, m := range featureRef.FindAllStringSubmatch(src, -1) {
		if _, ok := scoring.Lookup(m[1] + "." + m[2]); !ok {
			return fmt.Errorf("unknown feature %s.%s", m[1], m[2])
		}
	}
	return nil
}
