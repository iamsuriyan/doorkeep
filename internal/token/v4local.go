// Package token mints and verifies doorkeep result tokens.
//
// Tokens are PASETO v4.local (XChaCha20 + keyed BLAKE2b-256 MAC), implemented
// here directly from the specification on golang.org/x/crypto primitives and
// tested against the official paseto-standard test vectors
// (testdata/v4.json). Rationale for PASETO over JWT: no algorithm field to
// confuse, and claims are encrypted so the client cannot read its own risk
// score (design section 2.6).
package token

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
)

const v4LocalHeader = "v4.local."

// KeySize is the symmetric key length for v4.local.
const KeySize = 32

var (
	// ErrToken is returned for any malformed, forged or undecryptable token.
	// Callers must not distinguish failure causes to clients.
	ErrToken = errors.New("token: invalid")

	// Strict rejects non-canonical encodings (non-zero padding bits), which
	// would otherwise make tokens malleable (official vector 4-F-4).
	b64 = base64.RawURLEncoding.Strict()
)

// pae is PASETO pre-authentication encoding.
func pae(pieces ...[]byte) []byte {
	size := 8
	for _, p := range pieces {
		size += 8 + len(p)
	}
	out := make([]byte, 0, size)
	out = binary.LittleEndian.AppendUint64(out, uint64(len(pieces))&^(1<<63))
	for _, p := range pieces {
		out = binary.LittleEndian.AppendUint64(out, uint64(len(p))&^(1<<63))
		out = append(out, p...)
	}
	return out
}

func deriveKeys(key, n []byte) (ek, n2, ak []byte, err error) {
	h, err := blake2b.New(56, key)
	if err != nil {
		return nil, nil, nil, err
	}
	h.Write([]byte("paseto-encryption-key"))
	h.Write(n)
	tmp := h.Sum(nil)
	ek, n2 = tmp[:32], tmp[32:56]

	h2, err := blake2b.New256(key)
	if err != nil {
		return nil, nil, nil, err
	}
	h2.Write([]byte("paseto-auth-key-for-aead"))
	h2.Write(n)
	ak = h2.Sum(nil)
	return ek, n2, ak, nil
}

func mac(ak, preAuth []byte) ([]byte, error) {
	h, err := blake2b.New256(ak)
	if err != nil {
		return nil, err
	}
	h.Write(preAuth)
	return h.Sum(nil), nil
}

// encryptV4Local encrypts message with a caller-supplied 32-byte nonce. Only
// tests pass a fixed nonce; production uses Encrypt.
func encryptV4Local(key, message, footer, implicit, n []byte) (string, error) {
	if len(key) != KeySize || len(n) != 32 {
		return "", ErrToken
	}
	ek, n2, ak, err := deriveKeys(key, n)
	if err != nil {
		return "", err
	}
	c := make([]byte, len(message))
	s, err := chacha20.NewUnauthenticatedCipher(ek, n2)
	if err != nil {
		return "", err
	}
	s.XORKeyStream(c, message)
	t, err := mac(ak, pae([]byte(v4LocalHeader), n, c, footer, implicit))
	if err != nil {
		return "", err
	}
	body := make([]byte, 0, 32+len(c)+32)
	body = append(append(append(body, n...), c...), t...)
	tok := v4LocalHeader + b64.EncodeToString(body)
	if len(footer) > 0 {
		tok += "." + b64.EncodeToString(footer)
	}
	return tok, nil
}

// Encrypt produces a v4.local token with a random nonce.
func Encrypt(key, message, footer, implicit []byte) (string, error) {
	n := make([]byte, 32)
	if _, err := rand.Read(n); err != nil {
		return "", err
	}
	return encryptV4Local(key, message, footer, implicit, n)
}

// Footer returns the decoded (unauthenticated) footer so callers can pick a
// key by key id before decrypting. It must be treated as untrusted until
// Decrypt succeeds.
func Footer(tok string) ([]byte, error) {
	if !strings.HasPrefix(tok, v4LocalHeader) {
		return nil, ErrToken
	}
	parts := strings.Split(tok[len(v4LocalHeader):], ".")
	switch len(parts) {
	case 1:
		return nil, nil
	case 2:
		f, err := b64.DecodeString(parts[1])
		if err != nil {
			return nil, ErrToken
		}
		return f, nil
	}
	return nil, ErrToken
}

// Decrypt verifies and decrypts a v4.local token. The footer is checked as
// part of the MAC; implicit is the implicit assertion the token was minted
// with.
func Decrypt(key []byte, tok string, implicit []byte) (message, footer []byte, err error) {
	if len(key) != KeySize || !strings.HasPrefix(tok, v4LocalHeader) {
		return nil, nil, ErrToken
	}
	parts := strings.Split(tok[len(v4LocalHeader):], ".")
	if len(parts) < 1 || len(parts) > 2 {
		return nil, nil, ErrToken
	}
	body, err := b64.DecodeString(parts[0])
	if err != nil || len(body) < 64 {
		return nil, nil, ErrToken
	}
	if len(parts) == 2 {
		if footer, err = b64.DecodeString(parts[1]); err != nil {
			return nil, nil, ErrToken
		}
	}
	n, c, t := body[:32], body[32:len(body)-32], body[len(body)-32:]
	ek, n2, ak, err := deriveKeys(key, n)
	if err != nil {
		return nil, nil, ErrToken
	}
	t2, err := mac(ak, pae([]byte(v4LocalHeader), n, c, footer, implicit))
	if err != nil || subtle.ConstantTimeCompare(t, t2) != 1 {
		return nil, nil, ErrToken
	}
	m := make([]byte, len(c))
	s, err := chacha20.NewUnauthenticatedCipher(ek, n2)
	if err != nil {
		return nil, nil, ErrToken
	}
	s.XORKeyStream(m, c)
	return m, footer, nil
}
