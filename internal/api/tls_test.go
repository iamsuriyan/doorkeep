package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestForgedPayloadOverGoTLS: an attacker scripts /v1/submit from Go with a
// perfect human payload and Chrome headers. The handshake gives it away.
func TestForgedPayloadOverGoTLS(t *testing.T) {
	h := newHarness(t)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: h.srv}
	tl, _ := ConfigureTLS(hs, ln, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}})
	go hs.Serve(tl)
	defer hs.Close()
	base := "https://localhost:" + strings.Split(ln.Addr().String(), ":")[1]
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}}

	do := func(path, body string) map[string]any {
		req, _ := http.NewRequest("POST", base+path, strings.NewReader(body))
		for k, v := range browserHeaders() {
			req.Header.Set(k, v)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		var out map[string]any
		json.Unmarshal(b, &out)
		return out
	}
	sess := do("/v1/session", `{"sk":"dk_pk_shop","a":"signup"}`)
	n := sess["nonce"].(string)
	h.clock = h.clock.Add(12 * time.Second)
	out := do("/v1/submit", encode(humanPayloadAfter(n, 12*time.Second)))
	var reasons []string
	if tok, _ := out["token"].(string); tok != "" {
		dk := h.verify(tok, h.secret, nil)["doorkeep"].(map[string]any)
		reasons = anyStrings(dk["reasons"])
		t.Logf("forged over Go TLS: risk=%v outcome=%v reasons=%v", dk["risk"], dk["outcome"], reasons)
	} else {
		evs, _ := h.srv.Store.ListEvents(t.Context(), storeFilterAll())
		for _, r := range evs[0].Reasons {
			reasons = append(reasons, r.Code)
		}
		t.Logf("forged over Go TLS: status=%v reasons=%v", out["status"], reasons)
	}
	for _, want := range []string{"UA_TLS_MISMATCH", "UA_H2_MISMATCH"} {
		if !slices.Contains(reasons, want) {
			t.Errorf("missing %s in %v", want, reasons)
		}
	}
}
