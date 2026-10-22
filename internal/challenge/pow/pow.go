// Package pow implements the proof-of-work fallback challenge (design
// section 5.1): many small SHA-256 sub-puzzles so solve time is tightly
// concentrated, bound to the nonce id and a per-challenge salt.
package pow

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"math/bits"
)

// Params describe one challenge.
type Params struct {
	Salt string `json:"salt"` // base64url 16 bytes
	Bits int    `json:"bits"` // leading zero bits per sub-puzzle
	N    int    `json:"n"`    // number of sub-puzzles
}

// MaxExpectedHashesMobile caps difficulty for mobile user agents.
const MaxExpectedHashesMobile = 200_000

// ForRisk picks difficulty by risk band (design table 5.1). attack raises
// difficulty when the site is under elevated load.
func ForRisk(risk int, mobile, attack bool) Params {
	p := Params{Salt: newSalt()}
	switch {
	case attack && !mobile:
		p.Bits, p.N = 14, 32
	case risk >= 62 || attack:
		p.Bits, p.N = 13, 24
	case risk >= 50:
		p.Bits, p.N = 12, 24
	default:
		p.Bits, p.N = 12, 10
	}
	if mobile {
		for Expected(p) > MaxExpectedHashesMobile && p.N > 4 {
			p.N--
		}
	}
	return p
}

// Expected returns the expected number of hashes to solve p.
func Expected(p Params) int { return p.N << p.Bits }

func newSalt() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// preimage is nonceID || salt || uint32be(i) || uint32be(x).
func digest(nonceID, salt string, i, x uint32) [32]byte {
	buf := make([]byte, 0, len(nonceID)+len(salt)+8)
	buf = append(buf, nonceID...)
	buf = append(buf, salt...)
	buf = binary.BigEndian.AppendUint32(buf, i)
	buf = binary.BigEndian.AppendUint32(buf, x)
	return sha256.Sum256(buf)
}

func leadingZeros(h [32]byte) int {
	n := 0
	for _, b := range h {
		if b == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(b)
	}
	return n
}

// Verify checks a solution with N hashes.
func Verify(nonceID string, p Params, solution []uint32) bool {
	if len(solution) != p.N || p.N == 0 || p.Bits <= 0 || p.Bits > 32 {
		return false
	}
	for i, x := range solution {
		if leadingZeros(digest(nonceID, p.Salt, uint32(i), x)) < p.Bits {
			return false
		}
	}
	return true
}

// Solve finds a solution (used by tests and the Go verify client's
// self-test; browsers solve in the snippet's worker).
func Solve(nonceID string, p Params) []uint32 {
	out := make([]uint32, p.N)
	for i := 0; i < p.N; i++ {
		for x := uint32(0); ; x++ {
			if leadingZeros(digest(nonceID, p.Salt, uint32(i), x)) >= p.Bits {
				out[i] = x
				break
			}
		}
	}
	return out
}
