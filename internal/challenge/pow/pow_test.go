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
	sol[0]++
	if Verify("nonce-abc", p, sol) && leadingZeros(digest("nonce-abc", p.Salt, 0, sol[0])) < p.Bits {
		t.Fatal("tampered solution accepted")
	}
	if Verify("nonce-abc", p, sol[:3]) {
		t.Fatal("short solution accepted")
	}
}

func TestMobileCap(t *testing.T) {
	for _, risk := range []int{40, 55, 70} {
		p := ForRisk(risk, true, true)
		if Expected(p) > MaxExpectedHashesMobile {
			t.Fatalf("risk %d mobile expected %d", risk, Expected(p))
		}
	}
}
