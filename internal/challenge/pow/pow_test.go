package pow

import "testing"

func TestSolveVerify(t *testing.T) {
	p := Params{Salt: "c2FsdHNhbHRzYWx0c2FsdA", Bits: 8, N: 6}
	sol := Solve("nonce-abc", p)
	if !Verify("nonce-abc", p, sol) {
		t.Fatal("valid solution rejected")
	}
	if Verify("nonce-other", p, sol) {
		t.Fatal("solution accepted for a different nonce")
	}
	if Verify("nonce-abc", Params{Salt: "b3RoZXJzYWx0b3RoZXJzYQ", Bits: 8, N: 6}, sol) {
		t.Fatal("solution accepted for a different salt")
	}
	if Verify("nonce-abc", p, sol[:3]) {
		t.Fatal("short solution accepted")
	}
	if Verify("nonce-abc", p, append(sol, 0)) {
		t.Fatal("long solution accepted")
	}
}

// TestTamperedSolutionRejected replaces one sub-solution with a value that
// does not meet the difficulty and expects rejection.
func TestTamperedSolutionRejected(t *testing.T) {
	p := Params{Salt: "c2FsdHNhbHRzYWx0c2FsdA", Bits: 8, N: 6}
	sol := Solve("nonce-abc", p)
	bad := sol[2]
	for leadingZeros(digest("nonce-abc", p.Salt, 2, bad)) >= p.Bits {
		bad++
	}
	tampered := append([]uint32(nil), sol...)
	tampered[2] = bad
	if Verify("nonce-abc", p, tampered) {
		t.Fatal("tampered solution accepted")
	}
}

func TestInvalidParamsRejected(t *testing.T) {
	for _, p := range []Params{{Bits: 0, N: 1}, {Bits: 33, N: 1}, {Bits: 8, N: 0}} {
		if Verify("n", p, make([]uint32, p.N)) {
			t.Fatalf("params %+v accepted", p)
		}
	}
}

func TestMobileCap(t *testing.T) {
	for _, attack := range []bool{false, true} {
		for _, risk := range []int{35, 40, 55, 62, 70} {
			p := ForRisk(risk, true, attack)
			if Expected(p) > MaxExpectedHashesMobile {
				t.Fatalf("risk %d attack %v: mobile expected %d", risk, attack, Expected(p))
			}
		}
	}
}

func TestDifficultyRisesWithRiskAndAttack(t *testing.T) {
	low, high := Expected(ForRisk(40, false, false)), Expected(ForRisk(70, false, false))
	if high <= low {
		t.Fatalf("risk 70 (%d hashes) not harder than risk 40 (%d)", high, low)
	}
	if a := Expected(ForRisk(40, false, true)); a <= high {
		t.Fatalf("attack mode (%d hashes) not harder than the top band (%d)", a, high)
	}
	a, b := ForRisk(40, false, false), ForRisk(40, false, false)
	if a.Salt == b.Salt {
		t.Fatal("salt reused")
	}
}
