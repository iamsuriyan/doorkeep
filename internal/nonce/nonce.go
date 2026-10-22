// Package nonce implements the one-time session nonce that binds snippet
// execution, optional challenge, token minting and backend verification
// (design section 2.3). All state changes are compare-and-set transitions so
// a nonce can be submitted, solved, minted and verified at most once.
package nonce

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"
)

// State is the nonce lifecycle state.
type State string

const (
	Issued           State = "issued"
	Submitted        State = "submitted"
	ChallengedPoW    State = "challenged_pow"
	ChallengedVisual State = "challenged_visual"
	Solved           State = "solved"
	Minted           State = "minted"
	Verified         State = "verified"
	Burned           State = "burned"
)

// Nonce is the stored record.
type Nonce struct {
	ID        string
	SiteID    string
	Origin    string
	Action    string
	Seed      string // base64url 8 bytes, drawn into canvas and probe order
	IssuedAt  time.Time
	ExpiresAt time.Time
	State     State
	IPHash    string // day-keyed HMAC of /24 or /48
	UAHash    string // SHA-256(UA header)[:8] hex
	PoWSalt   string
	PoWBits   int
	PoWN      int
	AnswerMAC string // HMAC(instance key, id||answer) for visual challenges
	Attempts  int
	EventID   string // event created at submit
	Risk      int    // risk recorded at submit, used when minting after a challenge
}

// Errors returned by stores. Callers map all of them to opaque client errors.
var (
	ErrNotFound   = errors.New("nonce: not found")
	ErrWrongState = errors.New("nonce: wrong state or expired")
)

// Store persists nonces. Implementations must make Transition atomic.
type Store interface {
	Create(ctx context.Context, n *Nonce) error
	Get(ctx context.Context, id string) (*Nonce, error)
	// Transition moves id from one of `from` to `to` if not expired at `now`,
	// applying mutate to the record in the same atomic step. It returns the
	// updated record or ErrWrongState.
	Transition(ctx context.Context, id string, from []State, to State, now time.Time, mutate func(*Nonce)) (*Nonce, error)
	// PurgeExpired deletes nonces whose expiry is older than before.
	PurgeExpired(ctx context.Context, before time.Time) (int64, error)
}

// TTLs from the design.
const (
	TTL          = 120 * time.Second
	ChallengeTTL = 10 * time.Minute
	MinElapsed   = 40 * time.Millisecond
	// Retention after expiry so a late /verify still sees "verified" and
	// returns timeout-or-duplicate rather than invalid.
	Retention = time.Hour
)

// NewID returns a random 16-byte base64url identifier.
func NewID() string { return randB64(16) }

// NewSeed returns a random 8-byte base64url seed.
func NewSeed() string { return randB64(8) }

func randB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("nonce: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
