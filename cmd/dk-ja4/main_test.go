package main

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/iamsuriyan/doorkeep/internal/api"
)

// TestForwardsFingerprints terminates real TLS with the handler, as dk-ja4
// does, and checks what the upstream receives over HTTP/1.1 and HTTP/2.
func TestForwardsFingerprints(t *testing.T) {
	got := make(chan http.Header, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	up, _ := url.Parse(upstream.URL)

	// Borrow httptest's self-signed certificate.
	ts := httptest.NewUnstartedServer(nil)
	ts.StartTLS()
	cert := ts.TLS.Certificates[0]
	pool := ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	ts.Close()

	hs := &http.Server{Handler: Handler(up)}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tln, err := api.ConfigureTLS(hs, ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	go hs.Serve(tln)
	defer hs.Close()

	for _, h2 := range []bool{false, true} {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"}, ForceAttemptHTTP2: h2}
		if !h2 {
			tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		}
		req, _ := http.NewRequest("GET", "https://"+ln.Addr().String()+"/x", nil)
		req.Header.Set("Doorkeep-TLS", "ja4=forged")
		req.Header.Set("Doorkeep-H2", "forged")
		res, err := (&http.Client{Transport: tr}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		hdr := <-got
		tlsHdr := hdr.Get("Doorkeep-TLS")
		if !strings.HasPrefix(tlsHdr, "ja4=t13") || strings.Contains(tlsHdr, "forged") {
			t.Fatalf("h2=%v: Doorkeep-TLS %q", h2, tlsHdr)
		}
		if h2 {
			if !strings.Contains(tlsHdr, "h2=1") || hdr.Get("Doorkeep-H2") == "" || hdr.Get("Doorkeep-H2") == "forged" {
				t.Fatalf("HTTP/2: TLS %q H2 %q", tlsHdr, hdr.Get("Doorkeep-H2"))
			}
		} else if hdr.Get("Doorkeep-H2") != "" {
			t.Fatalf("HTTP/1.1 kept a client-supplied Doorkeep-H2: %q", hdr.Get("Doorkeep-H2"))
		}
		if hdr.Get("X-Forwarded-For") == "" || hdr.Get("X-Forwarded-Proto") != "https" {
			t.Fatalf("forwarding headers missing: %v", hdr)
		}
	}
}
