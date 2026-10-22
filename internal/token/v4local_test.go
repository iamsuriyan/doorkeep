package token

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type vector struct {
	Name       string  `json:"name"`
	ExpectFail bool    `json:"expect-fail"`
	Key        string  `json:"key"`
	Nonce      string  `json:"nonce"`
	Token      string  `json:"token"`
	Payload    *string `json:"payload"`
	Footer     string  `json:"footer"`
	Implicit   string  `json:"implicit-assertion"`
}

func TestOfficialV4LocalVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/v4.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Tests []vector `json:"tests"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	ran := 0
	for _, v := range doc.Tests {
		if !strings.HasPrefix(v.Token, "v4.local.") || v.Key == "" {
			continue // public-key vectors and wrong-purpose vectors handled elsewhere
		}
		ran++
		t.Run(v.Name, func(t *testing.T) {
			key, _ := hex.DecodeString(v.Key)
			got, footer, err := Decrypt(key, v.Token, []byte(v.Implicit))
			if v.ExpectFail {
				if err == nil {
					t.Fatalf("expected failure, decrypted %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if string(got) != *v.Payload {
				t.Fatalf("payload mismatch:\n got %s\nwant %s", got, *v.Payload)
			}
			if string(footer) != v.Footer {
				t.Fatalf("footer mismatch: %q vs %q", footer, v.Footer)
			}
			nonce, _ := hex.DecodeString(v.Nonce)
			tok, err := encryptV4Local(key, []byte(*v.Payload), []byte(v.Footer), []byte(v.Implicit), nonce)
			if err != nil {
				t.Fatal(err)
			}
			if tok != v.Token {
				t.Fatalf("encrypt mismatch:\n got %s\nwant %s", tok, v.Token)
			}
		})
	}
	if ran < 8 {
		t.Fatalf("only %d v4.local vectors ran", ran)
	}
}

func TestTamperAndWrongKeyRejected(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	tok, err := Encrypt(key, []byte(`{"risk":12}`), []byte(`{"kid":"a"}`), []byte("site"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decrypt(key, tok, []byte("site")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decrypt(key, tok, []byte("other-site")); err == nil {
		t.Fatal("implicit assertion not enforced")
	}
	other := bytes.Repeat([]byte{8}, 32)
	if _, _, err := Decrypt(other, tok, []byte("site")); err == nil {
		t.Fatal("wrong key accepted")
	}
	b := []byte(tok)
	b[20] ^= 1
	if _, _, err := Decrypt(key, string(b), []byte("site")); err == nil {
		t.Fatal("tampered token accepted")
	}
	f, err := Footer(tok)
	if err != nil || string(f) != `{"kid":"a"}` {
		t.Fatalf("footer: %q %v", f, err)
	}
}
