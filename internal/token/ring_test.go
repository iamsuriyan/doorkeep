package token

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func key(id string, b byte) Key { return Key{ID: id, Secret: bytes.Repeat([]byte{b}, 32)} }

func TestRingMintOpenRoundTrip(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	r := &Ring{Active: key("k1", 1), Now: func() time.Time { return now }}
	tok, err := r.Mint(Claims{NonceID: "n1", SiteID: "s1", Risk: 42, Outcome: "allow", Reasons: []string{"A"}}, "dk_pk_a", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c, err := r.Open(tok, "dk_pk_a")
	if err != nil || c.NonceID != "n1" || c.Risk != 42 || c.IssuedAt != now.Unix() || c.ExpiresAt != now.Add(5*time.Minute).Unix() {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := r.Open(tok, "dk_pk_b"); !errors.Is(err, ErrToken) {
		t.Fatalf("opened for another site key: %v", err)
	}
	now = now.Add(5*time.Minute + time.Second)
	if _, err := r.Open(tok, "dk_pk_a"); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired token: %v", err)
	}
}

// Key rotation: tokens minted under the old key still open while it is in
// Older, and stop opening once it is dropped.
func TestRingRotation(t *testing.T) {
	old := &Ring{Active: key("k1", 1)}
	tok, err := old.Mint(Claims{NonceID: "n"}, "sk", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rotated := &Ring{Active: key("k2", 2), Older: []Key{key("k1", 1)}}
	if _, err := rotated.Open(tok, "sk"); err != nil {
		t.Fatalf("old-key token rejected during rotation: %v", err)
	}
	fresh, _ := rotated.Mint(Claims{NonceID: "m"}, "sk", time.Minute)
	if _, err := old.Open(fresh, "sk"); !errors.Is(err, ErrToken) {
		t.Fatal("token minted with the new key opened by a ring without it")
	}
	done := &Ring{Active: key("k2", 2)}
	if _, err := done.Open(tok, "sk"); !errors.Is(err, ErrToken) {
		t.Fatal("old-key token accepted after the old key was retired")
	}
	// Same key id, different secret: rejected (no silent key confusion).
	if _, err := (&Ring{Active: key("k1", 9)}).Open(tok, "sk"); !errors.Is(err, ErrToken) {
		t.Fatal("token opened with a different secret under the same id")
	}
}

func TestRingRejectsGarbage(t *testing.T) {
	r := &Ring{Active: key("k1", 1)}
	for _, tok := range []string{"", "v4.local.", "v4.local.AAAA", "v2.local.AAAA.e30", "not a token"} {
		if _, err := r.Open(tok, "sk"); err == nil {
			t.Errorf("%q accepted", tok)
		}
	}
}

// FuzzOpen checks that arbitrary input never panics, and that anything that
// opens carries exactly the claims a genuine mint produced (mutations of a
// real token must fail authentication). Fuzz workers re-run this setup, so
// the seed token differs per process; the claims check does not depend on it.
func FuzzOpen(f *testing.F) {
	r := &Ring{Active: key("k1", 1), Now: func() time.Time { return time.Unix(1_800_000_000, 0) }}
	tok, _ := r.Mint(Claims{NonceID: "genuine"}, "sk", time.Hour)
	f.Add(tok)
	f.Add("v4.local.")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		if c, err := r.Open(s, "sk"); err == nil && c.NonceID != "genuine" {
			t.Fatalf("forged token opened: %+v", c)
		}
	})
}
