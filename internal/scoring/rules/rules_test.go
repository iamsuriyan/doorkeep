package rules

import (
	"slices"
	"testing"

	"github.com/iamsuriyan/doorkeep/internal/scoring"
)

func builtin(t *testing.T) *Set {
	t.Helper()
	s, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func ids(h []Hit) []string {
	var out []string
	for _, x := range h {
		out = append(out, x.ID)
	}
	return out
}

func eval(t *testing.T, f scoring.Features, action string) Result {
	t.Helper()
	env := Context(f.Env(), action, []string{"signup", "login"})
	return builtin(t).Eval(env)
}

func TestBuiltinCompiles(t *testing.T) {
	s := builtin(t)
	if len(s.Rules()) < 40 {
		t.Fatalf("expected the full built-in set, got %d rules", len(s.Rules()))
	}
}

func TestEmptyVectorIsZeroRisk(t *testing.T) {
	// Neutral-when-absent: nothing known means nothing fires.
	r := eval(t, scoring.NewFeatures(), "signup")
	if r.Risk != 0 || len(r.Hits) != 0 {
		t.Fatalf("empty vector fired %v risk %d", ids(r.Hits), r.Risk)
	}
}

func TestDefaultHeadlessChromium(t *testing.T) {
	f := scoring.NewFeatures()
	f.Set("auto.wd", 1)
	f.SetBool("auto.headless_ua", true)
	f.SetCat("fp.gpu_class", "software")
	f.SetCat("fp.ua_family", "chrome")
	f.Set("beh.total_events", 0)
	f.Set("t.elapsed_s", 0.4)
	r := eval(t, f, "signup")
	want := []string{"HEADLESS_UA", "AUTOMATION_WEBDRIVER", "SOFTWARE_GPU", "NO_INTERACTION_FAST_SUBMIT"}
	for _, w := range want {
		if !slices.Contains(ids(r.Hits), w) {
			t.Errorf("missing %s in %v", w, ids(r.Hits))
		}
	}
	if r.Risk != 100 {
		t.Errorf("risk %d, want 100", r.Risk)
	}
}

func TestKeyboardOnlyHumanIsLowRisk(t *testing.T) {
	// Screen-reader / keyboard user: no pointer at all, natural typing.
	f := scoring.NewFeatures()
	f.Set("auto.wd", 0)
	f.SetCat("fp.ua_family", "firefox")
	f.SetCat("auto.eng", "spidermonkey")
	f.SetCat("fp.gpu_class", "hardware")
	f.Set("beh.total_events", 42)
	f.Set("beh.key_count", 42)
	f.Set("beh.key_hold_mean", 85)
	f.Set("beh.key_hold_cv", 0.3)
	f.Set("beh.key_interval_cv", 0.5)
	f.Set("beh.untrusted_frac", 0)
	f.Set("t.elapsed_s", 25)
	r := eval(t, f, "signup")
	if r.Risk >= 35 {
		t.Fatalf("keyboard-only human risk %d, fired %v", r.Risk, ids(r.Hits))
	}
}

func TestPrivacyBrowserNotPenalised(t *testing.T) {
	// Tor Browser: UTC, spoofed UA vs features, blank canvas, no WebGL.
	f := scoring.NewFeatures()
	f.SetBool("prof.rfp", true)
	f.SetBool("prof.tor", true)
	f.Set("fp.feat_mismatch", 4)
	f.SetBool("fp.tz_offset_mismatch", true)
	f.SetBool("fp.canvas_blocked", true)
	f.SetCat("fp.gpu_class", "software")
	f.SetBool("fp.font_os_mismatch", true)
	f.SetBool("net.ip_tor", true)
	f.Set("net.tz_ip_country_match", 0)
	r := eval(t, f, "signup")
	if r.Risk >= 35 {
		t.Fatalf("Tor Browser risk %d, fired %v", r.Risk, ids(r.Hits))
	}
	if !slices.Contains(ids(r.Hits), "PROFILE_RFP") {
		t.Fatalf("PROFILE_RFP not recorded: %v", ids(r.Hits))
	}
}

func TestShadowNeverChangesRisk(t *testing.T) {
	rs := []*Rule{
		{ID: "A", When: "auto.wd == 1", Weight: 40},
		{ID: "B", When: "auto.leaks >= 1", Weight: 50, Mode: ModeShadow},
	}
	s, err := Compile(rs, "t")
	if err != nil {
		t.Fatal(err)
	}
	f := scoring.NewFeatures()
	f.Set("auto.wd", 1)
	f.Set("auto.leaks", 2)
	r := s.Eval(Context(f.Env(), "x", nil))
	if r.Risk != 40 || r.ShadowRisk != 90 || len(r.Shadow) != 1 {
		t.Fatalf("risk %d shadow %d hits %v shadowHits %v", r.Risk, r.ShadowRisk, r.Hits, r.Shadow)
	}
}

func TestNeutralWhenAbsentProperty(t *testing.T) {
	// Removing any behaviour feature never increases risk when no automation
	// marker is present.
	base := scoring.NewFeatures()
	base.Set("auto.wd", 0)
	base.Set("beh.total_events", 60)
	base.Set("beh.ptr_samples", 50)
	base.Set("beh.ptr_straightness", 0.6)
	base.Set("beh.ptr_interval_cv", 0.4)
	base.Set("beh.untrusted_frac", 0)
	base.Set("beh.key_count", 10)
	base.Set("beh.key_hold_mean", 90)
	base.Set("beh.key_hold_cv", 0.3)
	base.Set("beh.key_interval_cv", 0.4)
	full := eval(t, base, "signup").Risk
	for k := range base.Num {
		if k[:4] != "beh." {
			continue
		}
		g := scoring.NewFeatures()
		for kk, v := range base.Num {
			if kk != k {
				g.Num[kk] = v
			}
		}
		if r := eval(t, g, "signup").Risk; r > full+15 {
			t.Errorf("removing %s raised risk from %d to %d", k, full, r)
		}
	}
}

func TestCompileRejectsTypos(t *testing.T) {
	_, err := Compile([]*Rule{{ID: "X", When: "autoo.wd == 1", Weight: 1}}, "t")
	if err == nil {
		t.Fatal("unknown identifier compiled")
	}
	_, err = Compile([]*Rule{{ID: "Y", When: "auto.wdd == 1", Weight: 1}}, "t")
	if err == nil {
		t.Fatal("unknown feature key compiled")
	}
}

func TestHumanEvidenceCannotCancelProof(t *testing.T) {
	f := scoring.NewFeatures()
	f.SetBool("net.canvas_seed_conflict", true)
	f.Set("beh.ptr_samples", 200)
	f.Set("beh.ptr_straightness", 0.5)
	f.Set("beh.ptr_interval_cv", 0.5)
	f.Set("beh.untrusted_frac", 0)
	f.Set("beh.key_count", 30)
	f.Set("beh.key_hold_cv", 0.3)
	f.Set("beh.key_interval_cv", 0.5)
	r := eval(t, f, "signup")
	if r.Risk < 90 {
		t.Fatalf("replay proof cancelled by replayed behaviour: risk %d hits %v", r.Risk, ids(r.Hits))
	}
}

func TestHumanEvidenceIgnoredWhenDeviceContradictsItself(t *testing.T) {
	f := scoring.NewFeatures()
	f.SetBool("fp.font_os_mismatch", true)
	f.Set("beh.ptr_samples", 120)
	f.Set("beh.ptr_straightness", 0.5)
	f.Set("beh.ptr_interval_cv", 0.5)
	f.Set("beh.untrusted_frac", 0)
	f.Set("beh.key_count", 20)
	f.Set("beh.key_hold_cv", 0.3)
	f.Set("beh.key_interval_cv", 0.5)
	r := eval(t, f, "signup")
	if r.Risk != 25 {
		t.Fatalf("human evidence offset a self-contradiction: risk %d hits %v", r.Risk, ids(r.Hits))
	}
}
