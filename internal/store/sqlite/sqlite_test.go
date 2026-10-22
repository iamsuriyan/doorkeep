package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/nonce"
	"github.com/iamsuriyan/doorkeep/internal/scoring"
	"github.com/iamsuriyan/doorkeep/internal/store"
)

func open(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "dk.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestSiteRoundTrip(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	s := &store.Site{ID: "s1", Name: "Example", SiteKey: "dk_pk_x", SecretHash: "abc", Origins: []string{"https://example.com"}, Mode: scoring.ModeEnforce}
	if err := db.CreateSite(ctx, s); err != nil {
		t.Fatal(err)
	}
	got, err := db.SiteByKey(ctx, "dk_pk_x")
	if err != nil || got.Origins[0] != "https://example.com" || got.ThresholdsFor("x") != scoring.DefaultThresholds {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := db.SiteByKey(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestNonceTransitionIsSingleUseUnderConcurrency(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	now := time.Now()
	n := &nonce.Nonce{ID: nonce.NewID(), SiteID: "s1", Origin: "https://e.com", Action: "a", Seed: nonce.NewSeed(),
		IssuedAt: now, ExpiresAt: now.Add(time.Minute), State: nonce.Issued}
	if err := db.Create(ctx, n); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := db.Transition(ctx, n.ID, []nonce.State{nonce.Issued}, nonce.Submitted, time.Now(), nil); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d concurrent submits succeeded, want exactly 1", wins.Load())
	}
}

func TestExpiredNonceRejected(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	now := time.Now()
	n := &nonce.Nonce{ID: nonce.NewID(), SiteID: "s1", State: nonce.Issued, IssuedAt: now, ExpiresAt: now.Add(time.Second)}
	_ = db.Create(ctx, n)
	if _, err := db.Transition(ctx, n.ID, []nonce.State{nonce.Issued}, nonce.Submitted, now.Add(2*time.Second), nil); !errors.Is(err, nonce.ErrWrongState) {
		t.Fatalf("expired transition: %v", err)
	}
}

func TestCanvasSeedConflict(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	now := time.Now()
	if c, _ := db.CanvasSeen(ctx, "s1", "hashA", "seed1", now, 24*time.Hour); c {
		t.Fatal("first sighting flagged")
	}
	if c, _ := db.CanvasSeen(ctx, "s1", "hashA", "seed1", now, 24*time.Hour); c {
		t.Fatal("same seed flagged")
	}
	if c, _ := db.CanvasSeen(ctx, "s1", "hashA", "seed2", now, 24*time.Hour); !c {
		t.Fatal("replay with new seed not flagged")
	}
	if c, _ := db.CanvasSeen(ctx, "s2", "hashA", "seed9", now, 24*time.Hour); c {
		t.Fatal("cross-site sighting flagged")
	}
}

func TestEventRoundTrip(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	f := scoring.NewFeatures()
	f.Set("auto.wd", 1)
	f.SetCat("fp.ua_family", "chrome")
	e := &store.Event{ID: "evt_1", SiteID: "s1", TS: time.Now(), Action: "signup", Risk: 80, Outcome: scoring.Block, WouldBe: scoring.Block,
		Reasons: []scoring.Reason{{Code: "AUTOMATION_WEBDRIVER", Weight: 45}}, Features: f, FPHash: "fp1", IP24Hash: "ip1"}
	if err := db.InsertEvent(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, err := db.ListEvents(ctx, store.EventFilter{SiteID: "s1", Reason: "AUTOMATION_WEBDRIVER"})
	if err != nil || len(got) != 1 || got[0].Features.Get("auto.wd") != 1 || got[0].Features.Cat["fp.ua_family"] != "chrome" {
		t.Fatalf("%v %+v", err, got)
	}
	if err := db.LabelEvent(ctx, "evt_1", "bot", "dashboard"); err != nil {
		t.Fatal(err)
	}
}
