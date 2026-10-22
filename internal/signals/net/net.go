// Package net derives server-side header-consistency features: User-Agent
// header vs navigator.userAgent, Client Hints, Fetch Metadata and
// Accept-Language (design section 3.3). It never rejects; it only reports.
package net

import (
	"net/http"
	"strings"

	"github.com/iamsuriyan/doorkeep/internal/scoring"
	"github.com/iamsuriyan/doorkeep/internal/signals/payload"
)

// Brave reports itself as Chrome, so it is covered by "chrome".
var chromium = map[string]bool{"chrome": true, "edge": true, "opera": true, "samsung": true}

// Secure reports whether the browser would treat the request as a secure
// context, which gates Client Hints and Fetch Metadata. X-Forwarded-Proto
// is honoured only when trustProxy says the request came from a configured
// proxy; otherwise any client could switch these checks on or off.
func Secure(r *http.Request, trustProxy bool) bool {
	if r.TLS != nil {
		return true
	}
	if trustProxy && strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]), "https") {
		return true
	}
	host := r.Host
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	return host == "localhost" || host == "127.0.0.1" || host == "[::1]" || strings.HasSuffix(host, ".localhost")
}

// Analyze sets net.* header features on f. trustProxy reports whether r
// came from a trusted proxy (see Secure).
func Analyze(f scoring.Features, r *http.Request, trustProxy bool, jsUA string, langs []string, c payload.Classified) {
	hdrUA := r.Header.Get("User-Agent")
	fam, major := payload.UAFamily(hdrUA)
	f.SetCat("net.ua_hdr_family", fam)
	if jsUA != "" {
		f.SetBool("net.ua_hdr_js_mismatch", hdrUA != jsUA)
	}

	switch r.ProtoMajor {
	case 1:
		f.Set("net.http_version", 1)
	case 2:
		f.Set("net.http_version", 2)
	case 3:
		f.Set("net.http_version", 3)
	}

	secure := Secure(r, trustProxy)
	chUA := r.Header.Get("Sec-CH-UA")
	// Every browser on iOS is WebKit: no Client Hints whatever its brand,
	// and Fetch Metadata as the iOS version's Safari.
	if payload.OSFamily(hdrUA) == "ios" {
		fam, major = "safari", payload.IOSMajor(hdrUA)
	}
	if secure {
		// Android WebView sends Client Hints only when the embedding app
		// opts in, so their absence there says nothing.
		if chromium[fam] && major >= 89 && chUA == "" && !payload.IsAndroidWebView(hdrUA) {
			f.SetBool("net.ch_missing", true)
		} else if chromium[fam] {
			f.SetBool("net.ch_missing", false)
		}
		if (fam == "firefox" || fam == "safari") && chUA != "" {
			f.SetBool("net.ch_unexpected", true)
		}
		if chUA != "" {
			mismatch := false
			if m := r.Header.Get("Sec-CH-UA-Mobile"); m != "" {
				mob := m == "?1"
				if mob != c.Mobile && c.OSFamily != "android" {
					mismatch = true
				}
			}
			if p := strings.Trim(strings.ToLower(r.Header.Get("Sec-CH-UA-Platform")), `"`); p != "" {
				want := map[string]string{"windows": "windows", "macos": "macos", "android": "android", "linux": "linux", "chromeos": "chrome os"}[payload.OSFamily(hdrUA)]
				if want != "" && p != want {
					mismatch = true
				}
			}
			f.SetBool("net.ch_mismatch", mismatch)
		}
		modern := (chromium[fam] && major >= 80) || (fam == "firefox" && major >= 90) || (fam == "safari" && major >= 17)
		if modern {
			f.SetBool("net.fetch_metadata_missing", r.Header.Get("Sec-Fetch-Mode") == "")
		}
	}

	al := r.Header.Get("Accept-Language")
	if al == "" {
		f.SetBool("net.accept_lang_missing", true)
	} else {
		f.SetBool("net.accept_lang_missing", false)
		if len(langs) > 0 {
			primary := strings.ToLower(strings.TrimSpace(strings.SplitN(strings.SplitN(al, ",", 2)[0], ";", 2)[0]))
			found := false
			for _, l := range langs {
				if strings.EqualFold(l, primary) || strings.EqualFold(strings.SplitN(l, "-", 2)[0], strings.SplitN(primary, "-", 2)[0]) {
					found = true
					break
				}
			}
			f.SetBool("net.accept_lang_mismatch", !found)
		}
	}
	if acc := r.Header.Get("Accept"); strings.HasPrefix(acc, "text/html") {
		f.SetBool("net.accept_wrong", true)
	}
}
