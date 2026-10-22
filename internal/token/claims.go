package token

import (
	"encoding/json"
	"errors"
	"time"
)

// Claims are the encrypted contents of a result token (design section 2.6).
type Claims struct {
	Iss       string   `json:"iss"`
	IssuedAt  int64    `json:"iat"` // unix seconds
	ExpiresAt int64    `json:"exp"` // unix seconds
	NonceID   string   `json:"jti"`
	SiteID    string   `json:"sid"`
	Origin    string   `json:"org"`
	Action    string   `json:"act"`
	EventID   string   `json:"eid"`
	Risk      int      `json:"risk"`
	Outcome   string   `json:"out"`
	Reasons   []string `json:"rc"`
	Challenge string   `json:"ch"`
	IP24      string   `json:"ip24,omitempty"`
	V         int      `json:"v"`
}

type footer struct {
	KID string `json:"kid"`
}

// Key is one symmetric token key with an identifier.
type Key struct {
	ID     string
	Secret []byte // 32 bytes
}

// Ring holds the active key used for minting and older keys still accepted
// for verification during rotation (two-key window).
type Ring struct {
	Active Key
	Older  []Key
	Now    func() time.Time
}

// ErrExpired is returned for well-formed tokens past their expiry.
var ErrExpired = errors.New("token: expired")

func (r *Ring) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Mint encrypts claims, binding the token to the site key via the implicit
// assertion so a token minted for one site cannot be opened as another.
func (r *Ring) Mint(c Claims, siteKey string, ttl time.Duration) (string, error) {
	now := r.now()
	c.Iss = "doorkeep"
	c.IssuedAt = now.Unix()
	c.ExpiresAt = now.Add(ttl).Unix()
	c.V = 1
	msg, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	f, _ := json.Marshal(footer{KID: r.Active.ID})
	return Encrypt(r.Active.Secret, msg, f, []byte(siteKey))
}

// Open decrypts and validates a token for the given site key. It returns the
// claims or ErrToken / ErrExpired.
func (r *Ring) Open(tok, siteKey string) (*Claims, error) {
	raw, err := Footer(tok)
	if err != nil {
		return nil, ErrToken
	}
	var f footer
	if len(raw) == 0 || json.Unmarshal(raw, &f) != nil {
		return nil, ErrToken
	}
	var key []byte
	for _, k := range append([]Key{r.Active}, r.Older...) {
		if k.ID == f.KID {
			key = k.Secret
			break
		}
	}
	if key == nil {
		return nil, ErrToken
	}
	msg, _, err := Decrypt(key, tok, []byte(siteKey))
	if err != nil {
		return nil, ErrToken
	}
	var c Claims
	if err := json.Unmarshal(msg, &c); err != nil || c.Iss != "doorkeep" || c.V != 1 {
		return nil, ErrToken
	}
	if r.now().Unix() > c.ExpiresAt {
		return nil, ErrExpired
	}
	return &c, nil
}
