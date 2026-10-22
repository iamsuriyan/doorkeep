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
	// Floor marks a rule as proof rather than evidence: when it fires, the
	// rules risk is at least its weight, so negative "human evidence" rules
	// (which an attacker can replay) can never cancel it.
	Floor       bool   `yaml:"floor,omitempty" json:"floor,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

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
	Risk       int   // max(clamp(sum enforced weights, 0, 100), Floor)
	Floor      int   // highest weight among fired floor rules
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
	floor, shadowFloor := 0, 0
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
			if r.Floor && r.Weight > shadowFloor {
				shadowFloor = r.Weight
			}
			continue
		}
		res.Hits = append(res.Hits, h)
		sum += r.Weight
		shadowSum += r.Weight
		if r.Floor {
			floor = max(floor, r.Weight)
			shadowFloor = max(shadowFloor, r.Weight)
		}
	}
	res.Risk = max(clamp(sum), floor)
	res.Floor = floor
	res.ShadowRisk = max(clamp(shadowSum), shadowFloor)
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

// Override is a per-site change to a rule. For a built-in rule only Mode and
// Weight apply; Custom rules carry a full definition.
type Override struct {
	Mode        Mode   `json:"mode,omitempty"`
	Weight      *int   `json:"weight,omitempty"`
	Custom      bool   `json:"custom,omitempty"`
	When        string `json:"when,omitempty"`
	Unless      string `json:"unless,omitempty"`
	Floor       bool   `json:"floor,omitempty"`
	Description string `json:"description,omitempty"`
}

// Effective builds a site's rule set from the built-ins plus overrides keyed
// by rule id. It fails if any expression does not compile, so a bad edit is
// rejected at save time rather than silently ignored.
func Effective(base *Set, overrides map[string]Override, version string) (*Set, error) {
	var out []*Rule
	seen := map[string]bool{}
	for _, r := range base.rules {
		c := *r
		c.when, c.unless = nil, nil
		if o, ok := overrides[r.ID]; ok && !o.Custom {
			if o.Mode != "" {
				c.Mode = o.Mode
			}
			if o.Weight != nil {
				c.Weight = *o.Weight
			}
		}
		out = append(out, &c)
		seen[r.ID] = true
	}
	ids := make([]string, 0, len(overrides))
	for id := range overrides {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		o := overrides[id]
		if !o.Custom {
			if !seen[id] {
				return nil, fmt.Errorf("rules: override for unknown rule %s", id)
			}
			continue
		}
		if seen[id] {
			return nil, fmt.Errorf("rules: custom rule %s collides with a built-in id", id)
		}
		w := 0
		if o.Weight != nil {
			w = *o.Weight
		}
		out = append(out, &Rule{ID: id, When: o.When, Unless: o.Unless, Weight: w, Mode: o.Mode, Floor: o.Floor, Description: o.Description})
	}
	return Compile(out, version)
}

// EvalOne evaluates a single rule from the set against env, ignoring its
// mode. Used by the rule lab to replay a rule over stored events.
func (s *Set) EvalOne(id string, env map[string]any) (fired bool, weight int, ok bool) {
	for _, r := range s.rules {
		if r.ID != id {
			continue
		}
		if !run(r.when, env) || (r.unless != nil && run(r.unless, env)) {
			return false, r.Weight, true
		}
		return true, r.Weight, true
	}
	return false, 0, false
}
