// Command measure terminates TLS with doorkeep's JA4 and HTTP/2
// fingerprinters and echoes what it observed, so classification tables can
// be built from real clients rather than from memory.
//
//	go run ./testing/tlsclients/measure -addr 127.0.0.1:18443
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/api"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18443", "listen address")
	flag.Parse()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}

	hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ja4, offers, h2, _ := api.DebugConnPrints(r)
		out := map[string]any{"ua": r.UserAgent(), "proto": r.Proto, "ja4": ja4, "offers_h2": offers}
		if h2 != nil {
			out["h2"] = h2.String()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	})}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	tl, _ := api.ConfigureTLS(hs, ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	log.Printf("measure listening on https://%s", *addr)
	go func() { <-context.Background().Done() }()
	log.Fatal(hs.Serve(tl))
}
