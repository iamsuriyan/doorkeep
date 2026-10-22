package model

import (
	"math/rand/v2"
	"testing"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/scoring"
)

// human draws a plausible human feature vector.
func human(r *rand.Rand) scoring.Features {
	f := scoring.NewFeatures()
	f.Set("auto.wd", 0)
	f.SetCat("fp.ua_family", []string{"chrome", "chrome", "chrome", "firefox", "safari"}[r.IntN(5)])
	f.Set("fp.hc_bucket", float64(1+r.IntN(3)))
	f.Set("beh.ptr_samples", float64(40+r.IntN(160)))
	f.Set("beh.ptr_straightness", 0.3+r.Float64()*0.5)
	f.Set("beh.ptr_interval_cv", 0.3+r.Float64()*0.9)
	f.Set("beh.ptr_speed_cv", 0.5+r.Float64()*1.5)
	f.Set("beh.key_count", float64(10+r.IntN(40)))
	f.Set("beh.key_hold_mean", 60+r.Float64()*80)
	f.Set("beh.key_hold_cv", 0.15+r.Float64()*0.4)
	f.Set("beh.key_interval_cv", 0.3+r.Float64()*0.8)
	f.Set("t.elapsed_s", 8+r.Float64()*60)
	return f
}

// robot is plausible in each feature's range but jointly unusual.
func robot() scoring.Features {
	f := scoring.NewFeatures()
	f.Set("auto.wd", 0)
	f.SetCat("fp.ua_family", "chrome")
	f.Set("fp.hc_bucket", 4)
	f.Set("beh.ptr_samples", 3)
	f.Set("beh.ptr_straightness", 0.99)
	f.Set("beh.ptr_interval_cv", 0.01)
	f.Set("beh.ptr_speed_cv", 0.01)
	f.Set("beh.key_count", 30)
	f.Set("beh.key_hold_mean", 2)
	f.Set("beh.key_hold_cv", 0.01)
	f.Set("beh.key_interval_cv", 0.01)
	f.Set("t.elapsed_s", 1.2)
	return f
}

func TestColdStartHasNoOpinion(t *testing.T) {
	h := NewHBOS(nil)
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < MinObservations-1; i++ {
		h.Observe(human(r))
	}
	if risk, _ := h.Score(robot(), nil); risk != 0 {
		t.Fatalf("cold model scored %d", risk)
	}
}

func TestHBOSSeparatesRobotFromHumans(t *testing.T) {
	h := NewHBOS(nil)
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 3000; i++ {
		h.Observe(human(r))
	}
	high := 0
	for i := 0; i < 200; i++ {
		if risk, _ := h.Score(human(r), nil); risk >= 50 {
			high++
		}
	}
	if high > 10 { // <= 5% of fresh humans may land in the top tail
		t.Fatalf("%d/200 fresh humans scored >= 50", high)
	}
	risk, cs := h.Score(robot(), nil)
	if risk < 90 {
		t.Fatalf("robot risk %d", risk)
	}
	t.Logf("robot risk %d, top features %v", risk, cs)
	if len(cs) == 0 || cs[0].Score <= 0 {
		t.Fatal("no explanation")
	}
}

func TestDecayForgetsOldBehaviour(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	h := NewHBOS(func() time.Time { return now })
	r := rand.New(rand.NewPCG(3, 4))
	// Two months of robot-like "normal" traffic, then four weeks of humans.
	for i := 0; i < 2000; i++ {
		h.Observe(robot())
	}
	now = now.Add(60 * 24 * time.Hour)
	for i := 0; i < 2000; i++ {
		h.Observe(human(r))
	}
	if risk, _ := h.Score(robot(), nil); risk < 50 {
		t.Fatalf("old behaviour not forgotten: robot risk %d", risk)
	}
}

func TestLogRegLearnsAndGatesPromotion(t *testing.T) {
	reg := NewRegistry(nil)
	r := rand.New(rand.NewPCG(5, 6))
	if reg.Promote("s", true) {
		t.Fatal("promoted with no labels")
	}
	for i := 0; i < 400; i++ {
		if i%2 == 0 {
			reg.Label("s", human(r), false, WeightStrong)
		} else {
			reg.Label("s", robot(), true, WeightStrong)
		}
	}
	st := reg.Status("s").LR
	if !st.Ready || st.Precision < 0.9 || st.Recall < 0.9 {
		t.Fatalf("supervised stats %+v", st)
	}
	if res := reg.Score("s", robot()); res.ShadowLR < 80 || res.Weight != WeightHBOS {
		t.Fatalf("shadow result %+v", res)
	}
	if !reg.Promote("s", true) {
		t.Fatal("promotion refused when ready")
	}
	if res := reg.Score("s", robot()); res.Risk < 80 || res.Weight != WeightPromoted {
		t.Fatalf("promoted result %+v", res)
	}
}

func TestOnlyLowRiskAllowedTrafficTrains(t *testing.T) {
	reg := NewRegistry(nil)
	reg.ObserveAllowed("s", robot(), 80, scoring.Block)
	reg.ObserveAllowed("s", robot(), 40, scoring.Allow)
	if reg.Status("s").HBOSObservations != 0 {
		t.Fatal("blocked or high-risk traffic trained the normal model")
	}
	reg.ObserveAllowed("s", robot(), 5, scoring.Allow)
	if reg.Status("s").HBOSObservations != 1 {
		t.Fatal("low-risk allowed traffic did not train")
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	reg := NewRegistry(nil)
	r := rand.New(rand.NewPCG(7, 8))
	for i := 0; i < 500; i++ {
		reg.ObserveAllowed("s", human(r), 0, scoring.Allow)
		reg.Label("s", robot(), true, WeightWeak)
	}
	before := reg.Score("s", robot())
	reg2 := NewRegistry(nil)
	if err := reg2.Restore(reg.Snapshot()); err != nil {
		t.Fatal(err)
	}
	after := reg2.Score("s", robot())
	if before.Risk != after.Risk || before.ShadowLR != after.ShadowLR {
		t.Fatalf("snapshot changed scores: %+v vs %+v", before, after)
	}
}

// TestRegistryConcurrent exercises scoring, labelling and promotion from
// several goroutines; run with -race.
func TestRegistryConcurrent(t *testing.T) {
	reg := NewRegistry(time.Now)
	done := make(chan struct{})
	for g := range 4 {
		go func() {
			defer func() { done <- struct{}{} }()
			r := rand.New(rand.NewPCG(uint64(g), 1))
			for i := range 300 {
				f := human(r)
				switch i % 4 {
				case 0:
					reg.Label("s", f, i%8 == 0, 1)
				case 1:
					reg.Promote("s", i%2 == 0)
				case 2:
					reg.ObserveAllowed("s", f, 0, scoring.Allow)
				default:
					reg.Score("s", f)
				}
			}
		}()
	}
	for range 4 {
		<-done
	}
	// Scoring the global model directly must not self-deadlock.
	reg.Score(GlobalID, robot())
}
