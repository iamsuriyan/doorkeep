package scoring

import "testing"

func TestAllowListWinsOverEverything(t *testing.T) {
	for risk := 0; risk <= 100; risk += 10 {
		d := Combine(risk, nil, nil, risk, 100, 1, ListAllow, "ALLOWLIST_IP", DefaultThresholds, ModeEnforce)
		if d.Risk != 0 || d.Outcome != Allow {
			t.Fatalf("allow-list lost at risk %d: %+v", risk, d)
		}
	}
}

func TestModelNeverMovesAllowToBlock(t *testing.T) {
	for rules := 0; rules < DefaultThresholds.Challenge; rules++ {
		for model := 0; model <= 100; model += 5 {
			d := Combine(rules, nil, nil, rules, model, 1, "", "", DefaultThresholds, ModeEnforce)
			if d.Outcome == Block {
				t.Fatalf("rules %d model %d blocked", rules, model)
			}
			if d.Risk-rules > 40 {
				t.Fatalf("model added %d > 40", d.Risk-rules)
			}
		}
	}
}

func TestShadowNeverChangesEnforcedRisk(t *testing.T) {
	a := Combine(30, nil, nil, 30, 0, 0, "", "", DefaultThresholds, ModeEnforce)
	b := Combine(30, nil, []Reason{{Code: "X", Weight: 60}}, 90, 0, 0, "", "", DefaultThresholds, ModeEnforce)
	if a.Risk != b.Risk || a.Outcome != b.Outcome || b.ShadowRisk != 90 {
		t.Fatalf("shadow changed risk: %+v vs %+v", a, b)
	}
}

func TestModes(t *testing.T) {
	d := Combine(90, nil, nil, 90, 0, 0, "", "", DefaultThresholds, ModeMonitor)
	if d.Outcome != Allow || d.WouldBe != Block {
		t.Fatalf("monitor: %+v", d)
	}
	d = Combine(90, nil, nil, 90, 0, 0, "", "", DefaultThresholds, ModeChallengeOnly)
	if d.Outcome != Challenge {
		t.Fatalf("challenge_only: %+v", d)
	}
	d = Combine(5, nil, nil, 5, 0, 0, ListAlwaysChallenge, "ALWAYS_CHALLENGE_TOR", DefaultThresholds, ModeEnforce)
	if d.Outcome != Challenge {
		t.Fatalf("always_challenge: %+v", d)
	}
}

func TestChallengeCredit(t *testing.T) {
	d := Combine(50, nil, nil, 50, 0, 0, "", "", DefaultThresholds, ModeEnforce)
	d = ApplyChallengeCredit(d, 20, DefaultThresholds, ModeEnforce)
	if d.Outcome != Allow || d.Risk != 30 {
		t.Fatalf("pow credit: %+v", d)
	}
	d = Combine(95, nil, nil, 95, 0, 0, "", "", DefaultThresholds, ModeEnforce)
	d = ApplyChallengeCredit(d, 20, DefaultThresholds, ModeEnforce)
	if d.Outcome != Block {
		t.Fatalf("high risk should stay blocked after pow: %+v", d)
	}
}

func TestChallengeCannotClearProof(t *testing.T) {
	d := CombineWithFloor(80, 80, nil, nil, 80, 0, 0, "", "", DefaultThresholds, ModeEnforce)
	d = ApplyChallengeCredit(d, 20, DefaultThresholds, ModeEnforce)
	if d.Outcome != Block || d.Risk < 80 {
		t.Fatalf("proof cleared by PoW: %+v", d)
	}
	d = CombineWithFloor(45, 40, nil, nil, 45, 0, 0, "", "", DefaultThresholds, ModeEnforce)
	d = ApplyChallengeCredit(d, 20, DefaultThresholds, ModeEnforce)
	if d.Outcome != Block {
		t.Fatalf("floor in challenge band should not be cleared: %+v", d)
	}
}

func TestChallengeCreditByMode(t *testing.T) {
	th := DefaultThresholds
	cases := []struct {
		risk, floor, credit int
		mode                SiteMode
		want                Outcome
	}{
		{50, 0, 20, ModeEnforce, Allow},        // solved challenge clears the band
		{60, 60, 45, ModeEnforce, Block},       // proof floor holds risk in the band
		{90, 80, 45, ModeEnforce, Block},       // floor in the block band
		{90, 80, 45, ModeMonitor, Allow},       // monitor never enforces
		{90, 80, 45, ModeChallengeOnly, Allow}, // never block: the challenge is the gate
		{100, 0, 45, ModeChallengeOnly, Allow}, // block-band risk without a floor
		{40, 0, 20, ModeChallengeOnly, Allow},  //
		{60, 60, 45, ModeChallengeOnly, Allow}, // floor-held challenge band
	}
	for _, c := range cases {
		d := ApplyChallengeCredit(Decision{Risk: c.risk, Floor: c.floor, Outcome: Challenge}, c.credit, th, c.mode)
		if d.Outcome != c.want {
			t.Errorf("risk %d floor %d credit %d mode %s: outcome %s, want %s", c.risk, c.floor, c.credit, c.mode, d.Outcome, c.want)
		}
		if d.Risk < c.floor {
			t.Errorf("risk %d fell below floor %d", d.Risk, c.floor)
		}
	}
}

func TestChallengeOnlyNeverBlocks(t *testing.T) {
	for risk := 0; risk <= 100; risk += 5 {
		for _, list := range []ListAction{"", ListDeny, ListAlwaysChallenge} {
			d := Combine(risk, nil, nil, risk, 0, 0, list, "L", DefaultThresholds, ModeChallengeOnly)
			if d.Outcome == Block {
				t.Fatalf("challenge_only blocked at risk %d list %q", risk, list)
			}
		}
	}
}
