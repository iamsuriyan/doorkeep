package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/iamsuriyan/doorkeep/pkg/verify"
)

// TestGoVerifyClient exercises pkg/verify against a live server.
func TestGoVerifyClient(t *testing.T) {
	h := newHarness(t)
	n, _ := h.session("signup")
	h.clock = h.clock.Add(14 * time.Second)
	_, out := h.post("/v1/submit", encode(humanPayloadAfter(n, 14*time.Second)), browserHeaders())
	c := verify.New(h.http.URL, h.secret)
	ctx := context.Background()
	res, err := c.Verify(ctx, out["token"].(string), verify.Options{Action: "signup"})
	if err != nil || !res.Success || res.Doorkeep.Outcome != "allow" || res.Doorkeep.EventID == "" {
		t.Fatalf("verify: %+v %v", res, err)
	}
	if err := c.Report(ctx, res.Doorkeep.EventID, true); err != nil {
		t.Fatalf("report: %v", err)
	}
	if res, _ := c.Verify(ctx, "", verify.Options{}); res.Success {
		t.Fatal("empty token verified")
	}
	// Unreachable doorkeep: fail closed by default, open when asked.
	down := verify.New("http://127.0.0.1:1", "x")
	if _, err := down.Verify(ctx, "tok", verify.Options{}); !errors.Is(err, verify.ErrUnavailable) {
		t.Fatalf("fail-closed: %v", err)
	}
	down.Fail = verify.FailOpen
	if res, err := down.Verify(ctx, "tok", verify.Options{}); err != nil || !res.Success || !res.FailedOpen {
		t.Fatalf("fail-open: %+v %v", res, err)
	}
}
