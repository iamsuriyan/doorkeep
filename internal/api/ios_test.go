package api

import (
	"encoding/base64"
	"slices"
	"testing"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/signals/payload"
	"github.com/iamsuriyan/doorkeep/internal/store"
)

// Every browser on iOS runs Apple's WebKit (JavaScriptCore), sends no Client
// Hints, and supports what the iOS version's Safari supports, whatever its
// own version number says. Real iPhone users of Chrome, Firefox and Edge
// must not trip the browser-consistency rules.
func TestIOSBrowsersAreNotContradictions(t *testing.T) {
	const (
		ios     = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
		chrome  = ios + "CriOS/130.0.6723.90 Mobile/15E148 Safari/604.1"
		firefox = ios + "FxiOS/132.0 Mobile/15E148 Safari/605.1.15"
		edge    = ios + "EdgiOS/130.0.2849.80 Version/18.0 Mobile/15E148 Safari/604.1"
		safari  = ios + "Version/18.0 Mobile/15E148 Safari/604.1"
	)
	// iOS 18.0 WebKit: every probe except navigator.userAgentData (4) and
	// Iterator helpers (11, Safari 18.4).
	var bits uint16
	for i := 0; i < 12; i++ {
		if i != 4 && i != 11 {
			bits |= 1 << i
		}
	}
	feat := base64.RawURLEncoding.EncodeToString([]byte{byte(bits), byte(bits >> 8)})
	// Helvetica Neue, Menlo, Apple Color Emoji, Geneva (bits 6, 7, 9, 11).
	fonts := base64.RawURLEncoding.EncodeToString([]byte{1<<6 | 1<<7, 1<<1 | 1<<3, 0})

	for name, ua := range map[string]string{"chrome": chrome, "firefox": firefox, "edge": edge, "safari": safari} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			hdr := map[string]string{
				"Origin": origin, "User-Agent": ua, "Accept-Language": "en-IN,en;q=0.9", "Accept": "*/*",
				"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty",
			}
			_, out := h.post("/v1/session", `{"sk":"dk_pk_shop","a":"signup"}`, hdr)
			n := out["nonce"].(string)
			h.clock = h.clock.Add(12 * time.Second)
			p := humanPayloadAfter(n, 12*time.Second)
			p.FP.UA = ua
			p.FP.CV.H = n[:11]
			p.Auto.Eng = 2 // JavaScriptCore
			p.Auto.Chr = 0
			p.Auto.Plg = []int{5, 0}
			p.FP.Feat = feat
			p.FP.FN = fonts
			p.FP.GL = []string{"Apple Inc.", "Apple GPU"}
			p.FP.Scr = []float64{390, 844, 390, 844, 32, 3, 0}
			p.FP.MTP = 5
			p.FP.UAD = nil
			_, out = h.post("/v1/submit", encode(p), hdr)
			tok, ok := out["token"].(string)
			if !ok {
				ev, _ := h.srv.Store.ListEvents(t.Context(), store.EventFilter{SiteID: "site1", Limit: 1})
				t.Fatalf("real %s on iPhone was challenged: risk %d reasons %v", name, ev[0].Risk, ev[0].Reasons)
			}
			v := h.verify(tok, h.secret, nil)
			dk := v["doorkeep"].(map[string]any)
			var reasons []string
			for _, r := range dk["reasons"].([]any) {
				reasons = append(reasons, r.(string))
			}
			for _, bad := range []string{"UA_ENGINE_MISMATCH", "UA_CH_MISSING", "UA_FEATURE_MISMATCH", "FETCH_METADATA_MISSING", "FONT_OS_MISMATCH", "GPU_OS_MISMATCH"} {
				if slices.Contains(reasons, bad) {
					t.Errorf("%s fired for a real %s on iPhone (risk %v, reasons %v)", bad, name, dk["risk"], reasons)
				}
			}
			if dk["outcome"] != "allow" {
				t.Errorf("%s on iPhone: outcome %v risk %v reasons %v", name, dk["outcome"], dk["risk"], reasons)
			}
		})
	}
}

// In-app browsers (Instagram, Facebook, Gmail links) on Android are Android
// WebView: Chrome's engine and user agent, but no window.chrome object and
// no guaranteed Client Hints. Real users there must not look forged.
func TestAndroidWebViewAndChromeAreNotContradictions(t *testing.T) {
	const (
		webview = "Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/AP2A.240905.003; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/130.0.6723.102 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/485.0.0.0;]"
		chrome  = "Mozilla/5.0 (Linux; Android 14; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36"
	)
	// Every probe present except navigator.userAgentData in the WebView.
	allBits := uint16(1<<12 - 1)
	enc := func(b uint16) string { return base64.RawURLEncoding.EncodeToString([]byte{byte(b), byte(b >> 8)}) }
	// Roboto, Noto Color Emoji, Noto Sans (bits 12, 13, 15).
	fonts := base64.RawURLEncoding.EncodeToString([]byte{0, 1<<4 | 1<<5 | 1<<7, 0})
	cases := []struct {
		name, ua  string
		chr       int
		feat      string
		hints     bool
		uad       bool
		forbidden []string
	}{
		{"webview", webview, 2, enc(allBits &^ (1 << 4)), false, false, []string{"CHROME_OBJECT_FAKE", "UA_CH_MISSING", "UA_FEATURE_MISMATCH"}},
		{"chrome", chrome, 1, enc(allBits), true, true, []string{"CHROME_OBJECT_FAKE", "UA_CH_MISSING", "UA_CH_MISMATCH", "UA_CLIENT_HINTS_MISMATCH", "UA_FEATURE_MISMATCH", "MOBILE_WITHOUT_TOUCH"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			hdr := map[string]string{
				"Origin": origin, "User-Agent": c.ua, "Accept-Language": "en-IN,en;q=0.9", "Accept": "*/*",
				"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty",
			}
			if c.hints {
				hdr["Sec-CH-UA"] = `"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"`
				hdr["Sec-CH-UA-Mobile"] = "?1"
				hdr["Sec-CH-UA-Platform"] = `"Android"`
			}
			_, out := h.post("/v1/session", `{"sk":"dk_pk_shop","a":"signup"}`, hdr)
			n := out["nonce"].(string)
			h.clock = h.clock.Add(15 * time.Second)
			p := humanPayloadAfter(n, 15*time.Second)
			p.FP.UA, p.FP.CV.H, p.FP.Feat, p.FP.FN = c.ua, n[:11], c.feat, fonts
			p.Auto.Eng, p.Auto.Chr, p.Auto.Plg = 0, c.chr, []int{0, 1}
			p.FP.GL = []string{"Qualcomm", "Adreno (TM) 740"}
			p.FP.Scr = []float64{412, 915, 412, 915, 24, 2.6, 0}
			p.FP.MTP = 5
			if c.uad {
				p.FP.UAD = &payload.UAD{Brands: []string{"Chromium", "Google Chrome"}, Platform: "Android", Mobile: true}
			} else {
				p.FP.UAD = nil
			}
			_, out = h.post("/v1/submit", encode(p), hdr)
			ev, _ := h.srv.Store.ListEvents(t.Context(), store.EventFilter{SiteID: "site1", Limit: 1})
			var reasons []string
			for _, r := range ev[0].Reasons {
				reasons = append(reasons, r.Code)
			}
			for _, bad := range c.forbidden {
				if slices.Contains(reasons, bad) {
					t.Errorf("%s fired for a real Android %s (risk %d, reasons %v)", bad, c.name, ev[0].Risk, reasons)
				}
			}
			if out["status"] != "ok" || ev[0].Outcome != "allow" {
				t.Errorf("real Android %s: outcome %s risk %d reasons %v", c.name, ev[0].Outcome, ev[0].Risk, reasons)
			}
		})
	}
}
