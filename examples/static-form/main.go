// Command static-form is the smallest complete doorkeep integration: a
// plain HTML form, the snippet served same-origin through /_dk/, and a
// backend that verifies the token before doing anything.
//
//	DOORKEEP_URL=http://127.0.0.1:8080 DOORKEEP_SITE_KEY=dk_pk_... DOORKEEP_SECRET=dk_sk_... \
//	  go run ./examples/static-form
package main

import (
	"html"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	_ "embed"

	"github.com/iamsuriyan/doorkeep/pkg/verify"
)

//go:embed index.html
var page string

func main() {
	dk, key, secret := os.Getenv("DOORKEEP_URL"), os.Getenv("DOORKEEP_SITE_KEY"), os.Getenv("DOORKEEP_SECRET")
	if dk == "" || key == "" || secret == "" {
		log.Fatal("set DOORKEEP_URL, DOORKEEP_SITE_KEY and DOORKEEP_SECRET")
	}
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = "127.0.0.1:3000"
	}
	h, err := newHandler(dk, key, verify.New(dk, secret))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("open http://%s/ (create the doorkeep site with --origin http://%s)", addr, addr)
	log.Fatal(http.ListenAndServe(addr, h))
}

func newHandler(dkURL, siteKey string, v *verify.Client) (http.Handler, error) {
	up, err := url.Parse(dkURL)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	// Same-origin proxy: the snippet and its API calls go to /_dk/ on this
	// site, so no CORS and nothing a content blocker sees as third-party.
	// doorkeep must list this server in trusted_proxies to see client IPs.
	mux.Handle("/_dk/", http.StripPrefix("/_dk", &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(up)
		pr.SetXForwarded()
	}}))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(strings.ReplaceAll(page, "{{SITE_KEY}}", html.EscapeString(siteKey))))
	})
	mux.HandleFunc("POST /signup", func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		res, err := v.Verify(r.Context(), r.FormValue("dk-response"), verify.Options{Action: "signup", RemoteIP: ip})
		if err != nil || !res.Success {
			// Do not say why: the reasons are for you (log them), not for bots.
			if res != nil {
				log.Printf("signup refused: risk=%d outcome=%s reasons=%v errors=%v", res.Doorkeep.Risk, res.Doorkeep.Outcome, res.Doorkeep.Reasons, res.ErrorCodes)
			} else {
				log.Printf("signup refused: %v", err)
			}
			http.Error(w, "We could not verify this request. Please go back and try again.", http.StatusForbidden)
			return
		}
		// The check passed: create the account here.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("Welcome, " + r.FormValue("email") + "\n"))
	})
	return mux, nil
}
