// Command dk-ja4 is a small TLS-terminating front for sites whose own proxy
// (nginx, Caddy, Traefik, a CDN origin) terminates TLS and so hides the
// ClientHello from doorkeep. It terminates TLS itself, records the JA4 and
// HTTP/2 fingerprints exactly as doorkeep does, and forwards every request
// to an upstream with
//
//	Doorkeep-TLS: ja4=<JA4>; h2=<1|0>
//	Doorkeep-H2:  <settings|window|priority|pseudo>
//
// Headers of the same name sent by clients are removed first, so they cannot
// be forged through it. Add the address doorkeep sees these requests from to
// doorkeep's trusted_proxies.
//
//	dk-ja4 -listen :443 -cert cert.pem -key key.pem -upstream http://127.0.0.1:8080
//	dk-ja4 -listen :443 -autocert shop.example.com -upstream http://127.0.0.1:8080
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/iamsuriyan/doorkeep/internal/api"
)

func main() {
	listen := flag.String("listen", ":443", "TLS listen address")
	upstream := flag.String("upstream", "", "upstream URL, e.g. http://127.0.0.1:8080 (required)")
	cert := flag.String("cert", "", "certificate file (PEM)")
	key := flag.String("key", "", "private key file (PEM)")
	domains := flag.String("autocert", "", "comma-separated domains for automatic certificates (TLS-ALPN-01 on -listen)")
	cache := flag.String("autocert-cache", "./dk-ja4-acme", "directory for automatic certificates")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(*listen, *upstream, *cert, *key, *domains, *cache, log); err != nil {
		fmt.Fprintln(os.Stderr, "dk-ja4:", err)
		os.Exit(1)
	}
}

func run(listen, upstream, cert, key, domains, cache string, log *slog.Logger) error {
	if upstream == "" {
		return errors.New("-upstream is required")
	}
	up, err := url.Parse(upstream)
	if err != nil || up.Host == "" {
		return fmt.Errorf("invalid -upstream %q", upstream)
	}
	var tlsCfg *tls.Config
	switch {
	case cert != "" && key != "":
		c, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return err
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS12}
	case domains != "":
		m := &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist(strings.Split(domains, ",")...), Cache: autocert.DirCache(cache)}
		tlsCfg = m.TLSConfig()
		tlsCfg.MinVersion = tls.VersionTLS12
		tlsCfg.NextProtos = append([]string{"h2", "http/1.1"}, tlsCfg.NextProtos...)
	default:
		return errors.New("set -cert and -key, or -autocert")
	}
	hs := &http.Server{
		Handler:           Handler(up),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	if ln, err = api.ConfigureTLS(hs, ln, tlsCfg); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	log.Info("dk-ja4 listening", "addr", listen, "upstream", up.String())
	if err := hs.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Handler forwards requests to up with fingerprint headers set from the
// terminated connection.
func Handler(up *url.URL) http.Handler {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(up)
			pr.Out.Host = pr.In.Host // the site's own host, as a normal proxy would
			pr.SetXForwarded()
			pr.Out.Header.Del("Doorkeep-TLS")
			pr.Out.Header.Del("Doorkeep-H2")
			ja4, offersH2, h2, _ := api.DebugConnPrints(pr.In)
			if ja4 != "" {
				v := "ja4=" + ja4
				if offersH2 != nil {
					v += map[bool]string{true: "; h2=1", false: "; h2=0"}[*offersH2]
				}
				pr.Out.Header.Set("Doorkeep-TLS", v)
			}
			if h2 != nil {
				pr.Out.Header.Set("Doorkeep-H2", h2.String())
			}
		},
	}
	return rp
}
