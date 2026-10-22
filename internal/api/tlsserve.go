package api

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"

	"golang.org/x/net/http2"

	"github.com/iamsuriyan/doorkeep/internal/scoring"
	"github.com/iamsuriyan/doorkeep/internal/signals/h2fp"
	"github.com/iamsuriyan/doorkeep/internal/signals/tlsfp"
)

type ctxKey int

const (
	ctxTLSConn ctxKey = iota
	ctxH2Conn
)

// ConfigureTLS prepares hs to terminate TLS with fingerprinting: the
// listener records ClientHellos (JA4) and HTTP/2 connections are served
// through a tee that records the h2 fingerprint. Returns the listener to
// serve on.
func ConfigureTLS(hs *http.Server, ln net.Listener, tlsCfg *tls.Config) (net.Listener, error) {
	if tlsCfg.NextProtos == nil {
		tlsCfg.NextProtos = []string{"h2", "http/1.1"}
	}
	// x/net/http2.Server and ServeConn are deprecated in favour of
	// net/http's built-in HTTP/2, but net/http offers no way to serve an
	// HTTP/2 connection through a wrapper that records its first frames,
	// which the HTTP/2 fingerprint needs. They remain fully functional.
	//lint:ignore SA1019 see above
	h2s := &http2.Server{}
	hs.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		if tc, ok := c.(*tls.Conn); ok {
			if rc, ok := tc.NetConn().(*tlsfp.Conn); ok {
				ctx = context.WithValue(ctx, ctxTLSConn, rc)
			}
		}
		return ctx
	}
	hs.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
		"h2": func(srv *http.Server, c *tls.Conn, h http.Handler) {
			tee := &h2fp.Conn{Conn: c}
			ctx := context.WithValue(context.Background(), ctxH2Conn, tee)
			if rc, ok := c.NetConn().(*tlsfp.Conn); ok {
				ctx = context.WithValue(ctx, ctxTLSConn, rc)
			}
			//lint:ignore SA1019 see the note on h2s
			h2s.ServeConn(tee, &http2.ServeConnOpts{Context: ctx, Handler: h, BaseConfig: srv})
		},
	}
	return tls.NewListener(tlsfp.Listener{Listener: ln}, tlsCfg), nil
}

// connPrints returns the JA4 and h2 fingerprint observed for r, using the
// directly terminated connection or, from trusted proxies, the
// Doorkeep-TLS / Doorkeep-H2 headers. offersH2 is nil when unknown.
func (s *Server) connPrints(r *http.Request) (ja4 string, offersH2 *bool, h2 *h2fp.Print, h2Text string) {
	ja4, offersH2, h2, _ = s.connPrintsNoProxy(r)
	if ja4 == "" && s.fromTrustedProxy(r) {
		for _, part := range strings.Split(r.Header.Get("Doorkeep-TLS"), ";") {
			k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
			switch {
			case k == "ja4" && v != "":
				ja4 = v
			case k == "h2" && (v == "0" || v == "1"):
				b := v == "1"
				offersH2 = &b
			}
		}
		h2Text = r.Header.Get("Doorkeep-H2")
	}
	return
}

func (s *Server) fromTrustedProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	a, ok := netipFromIP(ip)
	return ok && s.Cfg.Trusted(a)
}

// DebugConnPrints exposes the fingerprints of a connection terminated with
// ConfigureTLS, without a Server (used by the measurement tool and dk-ja4).
func DebugConnPrints(r *http.Request) (string, *bool, *h2fp.Print, string) {
	return (&Server{}).connPrintsNoProxy(r)
}

func (s *Server) connPrintsNoProxy(r *http.Request) (ja4 string, offersH2 *bool, h2 *h2fp.Print, h2Text string) {
	if rc, ok := r.Context().Value(ctxTLSConn).(*tlsfp.Conn); ok {
		if h := rc.Hello(); h != nil {
			ja4 = h.JA4()
			v := h.OffersH2()
			offersH2 = &v
		}
	}
	if tee, ok := r.Context().Value(ctxH2Conn).(*h2fp.Conn); ok {
		h2 = tee.Print()
	}
	return
}

var browserFamilies = map[string]bool{"chrome": true, "edge": true, "opera": true, "samsung": true, "brave": true, "firefox": true, "safari": true}
var chromiumFamilies = map[string]bool{"chrome": true, "edge": true, "opera": true, "samsung": true, "brave": true}

// applyConnFeatures sets TLS and HTTP/2 consistency features. A mismatch is
// only reported when both sides are known; unknown prints never fire rules.
func applyConnFeatures(f scoring.Features, ja4 string, offersH2 *bool, h2 *h2fp.Print, h2Text, uaFamily, osFamily string) {
	tlsClass := tlsfp.Class(ja4)
	f.SetBool("net.tls_available", ja4 != "")
	f.SetCat("net.tls_class", tlsClass)
	if browserFamilies[uaFamily] {
		switch tlsClass {
		case "browser":
			f.SetBool("net.tls_ua_mismatch", false)
		case "openssl", "go", "node", "java", "okhttp":
			f.SetBool("net.tls_ua_mismatch", true)
		}
		if offersH2 != nil {
			f.SetBool("net.http1_on_h2", !*offersH2)
		}
	}
	h2Class := "none"
	if h2 != nil {
		h2Class = h2fp.Classify(h2)
	} else if h2Text != "" {
		h2Class = h2fp.ClassifyText(h2Text)
	}
	f.SetCat("net.h2_class", h2Class)
	if h2Class != "none" && h2Class != "other" && browserFamilies[uaFamily] {
		want := uaFamily
		if chromiumFamilies[uaFamily] {
			want = "chrome"
		}
		if osFamily == "ios" {
			want = "safari" // every iOS browser uses Apple's network stack
		}
		f.SetBool("net.h2_ua_mismatch", h2Class != want)
	}
}
