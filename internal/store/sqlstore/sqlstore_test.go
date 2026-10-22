package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/nonce"
	"github.com/iamsuriyan/doorkeep/internal/scoring"
	"github.com/iamsuriyan/doorkeep/internal/store"
)

// open returns the store under test: SQLite by default, Postgres when
// DK_TEST_POSTGRES holds a DSN (each test gets a fresh schema).
func open(t *testing.T) *DB {
	t.Helper()
	if dsn := os.Getenv("DK_TEST_POSTGRES"); dsn != "" {
		admin, err := sql.Open("pgx", dsn)
		if err != nil {
			t.Fatal(err)
		}
		schema := "t_" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_"))
		if _, err := admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE; CREATE SCHEMA " + schema); err != nil {
			t.Fatal(err)
		}
		admin.Close()
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		db, err := OpenPostgres(dsn + sep + "search_path=" + schema)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}
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

func TestAdminAndAuditAndLists(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	now := time.Now()
	if err := db.CreateAdmin(ctx, "ops", "hash", now); err != nil {
		t.Fatal(err)
	}
	if h, err := db.AdminPasswordHash(ctx, "ops"); err != nil || h != "hash" {
		t.Fatalf("%q %v", h, err)
	}
	if err := db.CreateSession(ctx, &store.AdminSession{TokenHash: "th", User: "ops", CSRF: "c", ExpiresAt: now.Add(time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	if s, err := db.GetSession(ctx, "th", now); err != nil || s.User != "ops" {
		t.Fatalf("%+v %v", s, err)
	}
	if _, err := db.GetSession(ctx, "th", now.Add(2*time.Hour)); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("expired session returned")
	}
	if err := db.Audit(ctx, store.AuditEntry{TS: now, Actor: "user:ops", Action: "x", Target: "y", Detail: map[string]any{"a": 1}}); err != nil {
		t.Fatal(err)
	}
	if l, _ := db.ListAudit(ctx, 10); len(l) != 1 || l[0].Detail["a"] != float64(1) {
		t.Fatalf("%+v", l)
	}
	e := &store.ListEntry{SiteID: "s1", Kind: "cidr", Value: "10.0.0.0/8", Action: scoring.ListAllow}
	if err := db.AddListEntry(ctx, e); err != nil || e.ID == 0 {
		t.Fatalf("list id %d %v", e.ID, err)
	}
	if err := db.SaveModels(ctx, map[string][]byte{"hbos:s1": []byte(`{"x":1}`)}, now); err != nil {
		t.Fatal(err)
	}
	if m, _ := db.LoadModels(ctx); string(m["hbos:s1"]) != `{"x":1}` {
		t.Fatalf("%v", m)
	}
	if err := db.PutAggregate(ctx, "s1", store.Aggregate{Hour: now.Truncate(time.Hour), Data: map[string]any{"total": 3}}); err != nil {
		t.Fatal(err)
	}
	if a, _ := db.Aggregates(ctx, "s1", now.Add(-2*time.Hour), now.Add(time.Hour)); len(a) != 1 {
		t.Fatalf("%v", a)
	}
}

func TestPurgeCanvas(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	now := time.Now()
	db.CanvasSeen(ctx, "s1", "old", "seed", now.Add(-48*time.Hour), 24*time.Hour)
	db.CanvasSeen(ctx, "s1", "new", "seed", now, 24*time.Hour)
	if n, err := db.PurgeCanvas(ctx, now.Add(-24*time.Hour)); err != nil || n != 1 {
		t.Fatalf("purged %d %v", n, err)
	}
	// The recent record still detects a replay.
	if c, _ := db.CanvasSeen(ctx, "s1", "new", "seed2", now, 24*time.Hour); !c {
		t.Fatal("recent canvas record was purged")
	}
}

func TestEventFilterEscapesWildcards(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	for i, code := range []string{"A_B", "AXB"} {
		e := &store.Event{ID: fmt.Sprintf("evt_%d", i), SiteID: "s1", TS: time.Now(), Action: "a", Outcome: scoring.Allow, WouldBe: scoring.Allow,
			Reasons: []scoring.Reason{{Code: code, Weight: 1}}, Features: scoring.NewFeatures(), FPHash: fmt.Sprintf("ab%d", i)}
		if err := db.InsertEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := db.ListEvents(ctx, store.EventFilter{SiteID: "s1", Reason: "A_B"}); len(got) != 1 {
		t.Fatalf("reason A_B matched %d events (underscore treated as a wildcard)", len(got))
	}
	if got, _ := db.ListEvents(ctx, store.EventFilter{SiteID: "s1", FPHash: "%"}); len(got) != 0 {
		t.Fatalf("fp %% matched %d events", len(got))
	}
	if got, _ := db.ListEvents(ctx, store.EventFilter{SiteID: "s1", FPHash: "ab"}); len(got) != 2 {
		t.Fatalf("fp prefix matched %d events", len(got))
	}
}

func TestAdminTokensExpireAndRevoke(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	now := time.Now()
	hash := strings.Repeat("ab", 32)
	if err := db.CreateAdminToken(ctx, hash, "ci", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateAdminToken(ctx, strings.Repeat("cd", 32), "forever", now, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if n, err := db.AdminTokenName(ctx, hash, now); err != nil || n != "ci" {
		t.Fatalf("%q %v", n, err)
	}
	if _, err := db.AdminTokenName(ctx, hash, now.Add(2*time.Hour)); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("expired token accepted")
	}
	toks, err := db.ListAdminTokens(ctx)
	if err != nil || len(toks) != 2 || toks[0].ID != hash[:store.AdminTokenIDLen] || toks[0].LastUsedAt == nil || toks[1].ExpiresAt != nil {
		t.Fatalf("%+v %v", toks, err)
	}
	if err := db.RevokeAdminToken(ctx, "%"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("wildcard revoke accepted")
	}
	if err := db.RevokeAdminToken(ctx, toks[1].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AdminTokenName(ctx, strings.Repeat("cd", 32), now); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("revoked token accepted")
	}
}

func TestKV(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	if _, err := db.GetKV(ctx, "k"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("missing key found")
	}
	for _, v := range []string{"1", "2"} {
		if err := db.PutKV(ctx, "k", v); err != nil {
			t.Fatal(err)
		}
	}
	if v, err := db.GetKV(ctx, "k"); err != nil || v != "2" {
		t.Fatalf("%q %v", v, err)
	}
}

func TestPurgeAggregates(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Hour)
	for _, h := range []time.Time{now.AddDate(-2, 0, 0), now.Add(-time.Hour)} {
		db.PutAggregate(ctx, "s1", store.Aggregate{Hour: h, Data: map[string]any{"total": 1}})
	}
	if n, err := db.PurgeAggregates(ctx, now.AddDate(-1, -1, 0)); err != nil || n != 1 {
		t.Fatalf("purged %d %v", n, err)
	}
	if a, _ := db.Aggregates(ctx, "s1", now.AddDate(-3, 0, 0), now); len(a) != 1 {
		t.Fatalf("left %d aggregates", len(a))
	}
}
