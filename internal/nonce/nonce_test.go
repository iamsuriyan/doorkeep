package nonce

import (
	"encoding/base64"
	"testing"
)

func TestIDsAreRandomAndSized(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		id := NewID()
		b, err := base64.RawURLEncoding.DecodeString(id)
		if err != nil || len(b) != 16 {
			t.Fatalf("id %q: %v", id, err)
		}
		if seen[id] {
			t.Fatal("duplicate id")
		}
		seen[id] = true
	}
	if b, _ := base64.RawURLEncoding.DecodeString(NewSeed()); len(b) != 8 {
		t.Fatal("seed size")
	}
}

func TestTTLOrdering(t *testing.T) {
	if !(MinElapsed < TTL && TTL < ChallengeTTL && ChallengeTTL < Retention) {
		t.Fatal("nonce lifetimes out of order")
	}
}
