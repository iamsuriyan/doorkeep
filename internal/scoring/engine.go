package scoring

// Outcome is the decision band for an event.
type Outcome string

const (
	Allow     Outcome = "allow"
	Challenge Outcome = "challenge"
	Block     Outcome = "block"
)

// SiteMode changes how outcomes are enforced for a site.
type SiteMode string

const (
	ModeEnforce       SiteMode = "enforce"
	ModeMonitor       SiteMode = "monitor"        // always mint allow; record would-be outcome
	ModeChallengeOnly SiteMode = "challenge_only" // never block; escalate to challenge
)

// Thresholds band risk into outcomes (design section 4.5).
type Thresholds struct {
	Challenge int `yaml:"t_challenge" json:"t_challenge"`
	Block     int `yaml:"t_block" json:"t_block"`
}

// DefaultThresholds are the shipped defaults.
var DefaultThresholds = Thresholds{Challenge: 35, Block: 75}

// Band maps risk to an outcome.
func (t Thresholds) Band(risk int) Outcome {
	switch {
	case risk >= t.Block:
		return Block
	case risk >= t.Challenge:
		return Challenge
	}
	return Allow
}

// ListAction is what a matching list entry does.
type ListAction string

const (
	ListAllow          ListAction = "allow"
	ListDeny           ListAction = "deny"
	ListAlwaysChallenge ListAction = "always_challenge"
)

// Reason is one contribution to a decision, rendered to operators.
type Reason struct {
	Code   string `json:"code"`
	Weight int    `json:"w"`
}

// Decision is the engine's output for one event.
type Decision struct {
	Risk          int      `json:"risk"`
	Outcome       Outcome  `json:"outcome"`        // enforced outcome
	WouldBe       Outcome  `json:"would_be"`       // outcome before site mode adjustments
	Reasons       []Reason `json:"reasons"`        // enforced + informational
	Shadow        []Reason `json:"shadow"`         // shadow contributions
	ShadowRisk    int      `json:"shadow_risk"`    // risk if shadow items were enforced
	ModelRisk     int      `json:"model_risk"`     // 0..100 from the model layer (0 when absent)
	ListMatched   string   `json:"list,omitempty"` // e.g. ALLOWLIST_ASN
}

// Combine applies list overrides, the model blend and site mode to a rules
// result. It is pure so it can be property-tested (design section 10.3):
//   - an allow-list match forces risk 0 and outcome allow;
//   - the model can add at most +40 and can never move allow to block;
//   - shadow contributions never change Risk.
func Combine(rulesRisk int, reasons, shadow []Reason, shadowRisk int,
	modelRisk int, modelWeight float64,
	list ListAction, listCode string,
	th Thresholds, mode SiteMode) Decision {

	d := Decision{Reasons: reasons, Shadow: shadow, ModelRisk: modelRisk}
	switch list {
	case ListAllow:
		d.Risk, d.Outcome, d.WouldBe, d.ListMatched = 0, Allow, Allow, listCode
		d.Reasons = append([]Reason{{Code: listCode}}, reasons...)
		d.ShadowRisk = 0
		return d
	case ListDeny:
		d.Risk, d.ListMatched = 100, listCode
		d.Reasons = append([]Reason{{Code: listCode, Weight: 100}}, reasons...)
	default:
		risk := rulesRisk
		if modelWeight > 0 && modelRisk > 0 {
			add := int(float64(modelRisk)*modelWeight + 0.5)
			if add > 40 {
				add = 40
			}
			// The model may push into challenge but never from allow to block.
			if th.Band(rulesRisk) == Allow && risk+add >= th.Block {
				add = th.Block - 1 - risk
			}
			if add > 0 {
				risk += add
				d.Reasons = append(d.Reasons, Reason{Code: "MODEL_ANOMALY", Weight: add})
			}
		}
		d.Risk = clamp(risk)
	}
	d.ShadowRisk = clamp(shadowRisk + (d.Risk - rulesRisk))
	if list == ListDeny {
		d.ShadowRisk = 100
	}
	d.WouldBe = th.Band(d.Risk)
	if list == ListAlwaysChallenge && d.WouldBe == Allow {
		d.WouldBe = Challenge
		d.ListMatched = listCode
		d.Reasons = append([]Reason{{Code: listCode}}, d.Reasons...)
	}
	d.Outcome = d.WouldBe
	switch mode {
	case ModeMonitor:
		d.Outcome = Allow
	case ModeChallengeOnly:
		if d.Outcome == Block {
			d.Outcome = Challenge
		}
	}
	return d
}

// ApplyChallengeCredit lowers risk after a solved challenge and re-bands it
// (design section 4.5). The final outcome never becomes better than what the
// strongest available challenge allows.
func ApplyChallengeCredit(d Decision, credit int, th Thresholds, mode SiteMode) Decision {
	d.Risk = clamp(d.Risk - credit)
	d.Reasons = append(d.Reasons, Reason{Code: "CHALLENGE_SOLVED", Weight: -credit})
	d.WouldBe = th.Band(d.Risk)
	if d.WouldBe == Challenge {
		// A solved challenge clears the challenge band.
		d.WouldBe = Allow
	}
	d.Outcome = d.WouldBe
	if mode == ModeMonitor {
		d.Outcome = Allow
	}
	return d
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
