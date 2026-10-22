package payload

import (
	"encoding/base64"
	"math"
	"strconv"
	"strings"

	"github.com/iamsuriyan/doorkeep/internal/scoring"
)

// ServerContext carries what the server measured itself for this submit, so
// normalisation can compute timing-truth features.
type ServerContext struct {
	ElapsedMS float64 // server wall time from nonce issue to submit
	NowMS     float64 // server wall clock at submit (unix ms)
}

// Normalise converts a validated payload into bucketed features. Raw values
// that must not be stored (UA string, WebGL strings, tz id, languages) are
// reduced to classes here; the returned Classified holds the few raw-derived
// values other server components need during the request only.
func Normalise(p *Payload, sc ServerContext) (scoring.Features, Classified) {
	f := scoring.NewFeatures()
	c := classify(p)

	// prof
	f.SetBool("prof.rfp", p.Prof.RFP || p.Prof.Tor)
	f.SetBool("prof.brave", p.Prof.Brave)
	f.SetBool("prof.tor", p.Prof.Tor)
	f.SetBool("prof.dnt", p.Prof.DNT)
	f.SetBool("prof.forced_colors", p.Prof.ForcedColors || p.FP.MQ&4 != 0)

	// auto
	f.Set("auto.wd", float64(p.Auto.WD))
	f.SetBool("auto.wd_tamper", p.Auto.WDT != 0)
	f.SetBool("auto.cdp", p.Auto.CDP)
	f.Set("auto.leaks", float64(p.Auto.Leaks))
	f.SetBool("auto.headless_ua", p.Auto.HUA || strings.Contains(p.FP.UA, "HeadlessChrome"))
	if len(p.Auto.Geo) >= 4 {
		iw, ih, ow, oh := p.Auto.Geo[0], p.Auto.Geo[1], p.Auto.Geo[2], p.Auto.Geo[3]
		full := at(p.Auto.Geo, 4) == 1
		f.SetBool("auto.outer_zero", ow == 0 || oh == 0)
		if !c.Mobile {
			f.SetBool("auto.outer_eq_inner", !full && ow == iw && oh == ih && ow > 0)
		}
		dpr := at(p.FP.Scr, 5)
		f.SetBool("auto.default_viewport", iw == 800 && ih == 600 && dpr == 1)
	}
	if len(p.Auto.Plg) == 2 {
		f.Set("auto.plugins", float64(p.Auto.Plg[0]))
		f.Set("auto.plugins_shape", float64(p.Auto.Plg[1]))
	}
	f.Set("auto.lang_count", float64(len(p.FP.Lang)))
	f.Set("auto.chrome_obj", float64(p.Auto.Chr))
	f.SetBool("auto.notif_contradiction", p.Auto.Notif)
	if p.Auto.Conn != 0 {
		f.SetBool("auto.conn_rtt_zero", p.Auto.Conn == 2)
	}
	switch {
	case p.Auto.Voices < 0:
		f.Set("auto.voices", 0)
	case p.Auto.Voices == 0:
		f.Set("auto.voices", 1)
	case p.Auto.Voices <= 5:
		f.Set("auto.voices", 2)
	default:
		f.Set("auto.voices", 3)
	}
	f.SetCat("auto.eng", []string{"v8", "spidermonkey", "jsc", "other"}[p.Auto.Eng])
	f.Set("auto.non_native_apis", float64(p.Auto.Nat))

	// fp
	f.SetCat("fp.ua_family", c.UAFamily)
	if c.UAMajor > 0 {
		f.Set("fp.ua_major", float64(c.UAMajor))
	}
	f.SetCat("fp.os_family", c.OSFamily)
	f.SetBool("fp.ua_mobile", c.Mobile)
	f.Set("fp.feat_mismatch", float64(featMismatch(c.UAFamily, c.UAMajor, p.FP.Feat)))
	if p.FP.UAD != nil {
		f.SetBool("fp.uad_mismatch", uadMismatch(p.FP.UAD, c))
	}
	sw := at(p.FP.Scr, 0)
	if c.Mobile {
		f.SetBool("fp.mobile_no_touch", p.FP.MTP == 0 && sw >= 1280)
	} else if c.UAFamily == "chrome" {
		f.SetBool("fp.desktop_coarse_pointer", p.FP.Tch&4 != 0 && p.FP.MTP == 0)
	}
	if !math.IsNaN(sw) {
		f.Set("fp.screen_w_bucket", math.Floor(sw/160))
	}
	if dpr := at(p.FP.Scr, 5); !math.IsNaN(dpr) {
		f.Set("fp.dpr_bucket", math.Round(dpr/0.25))
	}
	if c.OSFamily == "windows" && len(p.FP.Scr) >= 4 {
		f.SetBool("fp.avail_eq_screen", p.FP.Scr[3] == p.FP.Scr[1])
	}
	if p.FP.TZ != "" {
		f.SetBool("fp.tz_utc", c.TZUTC)
		if off, ok := tzStdOffsets[p.FP.TZ]; ok {
			// Accept either standard or DST offset (+-60 min).
			d := math.Abs(-p.FP.TZO - float64(off))
			f.SetBool("fp.tz_offset_mismatch", d != 0 && d != 60)
		}
		if c.TZCountry != "" {
			f.SetCat("fp.tz_country", c.TZCountry)
		}
	}
	if c.LangPrimary != "" {
		f.SetCat("fp.lang_primary", c.LangPrimary)
	}
	f.SetCat("fp.gpu_class", c.GPUClass)
	f.SetBool("fp.gpu_os_mismatch", gpuOSMismatch(p.FP.GL, c.OSFamily))
	f.SetBool("fp.canvas_blocked", p.FP.CV.B)
	f.SetBool("fp.audio_present", p.FP.AU != "")
	if p.FP.FN != "" {
		cls := fontOSClass(p.FP.FN)
		f.SetCat("fp.font_os_class", cls)
		f.SetBool("fp.font_os_mismatch", fontMismatch(cls, c.OSFamily))
	}
	if p.FP.HC > 0 {
		f.Set("fp.hc_bucket", scoring.BucketIndex(float64(p.FP.HC), 3, 5, 9, 17))
	}
	if p.FP.DM > 0 {
		f.Set("fp.dm_bucket", scoring.BucketIndex(p.FP.DM, 3, 5, 12))
	}
	f.Set("fp.touch_points", float64(p.FP.MTP))
	pc := 0.0
	fine, coarse := p.FP.Tch&16 != 0, p.FP.Tch&4 != 0
	switch {
	case fine && coarse:
		pc = 3
	case coarse:
		pc = 2
	case fine:
		pc = 1
	}
	f.Set("fp.pointer_class", pc)
	f.SetBool("fp.color_scheme_dark", p.FP.MQ&1 != 0)
	f.SetBool("fp.reduced_motion", p.FP.MQ&2 != 0)

	// beh: only set what was observed (neutral-when-absent).
	normaliseBehaviour(f, &p.Beh)

	// env
	perms := 0
	granted := 0
	allPrompt := true
	for i := 0; i < 5; i++ {
		s := (p.Env.Perm >> (2 * i)) & 3
		if s == 0 {
			continue
		}
		perms++
		if s != 1 {
			allPrompt = false
		}
		if s == 2 {
			granted++
		}
	}
	if perms > 0 {
		f.SetBool("env.perm_all_prompt", allPrompt)
		f.Set("env.perm_granted_count", float64(granted))
	}
	f.SetBool("env.storage_ok", p.Env.Sto&1 != 0)
	f.SetBool("env.storage_throws", p.Env.Sto&16 != 0)
	f.SetBool("env.cookies", p.Env.Sto&8 != 0)
	switch {
	case p.Env.Quota <= 0:
		f.Set("env.quota_bucket", 0)
	case p.Env.Quota < 1024:
		f.Set("env.quota_bucket", 1)
	case p.Env.Quota < 10240:
		f.Set("env.quota_bucket", 2)
	default:
		f.Set("env.quota_bucket", 3)
	}
	if tp := at(p.Env.Perf, 0); !math.IsNaN(tp) {
		f.Set("env.timer_precision", tp)
	}
	if dr := at(p.Env.Perf, 1); !math.IsNaN(dr) {
		f.Set("env.dom_ready_bucket", scoring.BucketIndex(dr, 50, 200, 1000, 5000))
	}
	if rc := at(p.Env.Perf, 2); !math.IsNaN(rc) {
		f.Set("env.resources_bucket", scoring.BucketIndex(rc, 1, 6, 31))
	}
	f.Set("env.snippet_version", float64(p.Env.SV))

	// t: timing truth
	if sc.ElapsedMS > 0 {
		f.Set("t.elapsed_s", sc.ElapsedMS/1000)
	}
	if p.T.S >= p.T.I {
		ce := (p.T.S - p.T.I) / 1000
		f.Set("t.client_elapsed_s", ce)
		if sc.ElapsedMS > 0 {
			f.SetBool("t.elapsed_mismatch", ce > sc.ElapsedMS/1000+1)
		}
	}
	if p.T.F > 0 && p.T.F >= p.T.I {
		f.Set("t.first_interaction_s", (p.T.F-p.T.I)/1000)
	}
	if sc.NowMS > 0 && p.T.D > 0 {
		f.Set("t.clock_skew_s", (p.T.D-sc.NowMS)/1000)
	}
	if p.FP.AU != "" && p.T.S-p.T.I < 20 {
		f.SetBool("t.collect_too_fast", true)
	}
	return f, c
}

func normaliseBehaviour(f scoring.Features, b *Beh) {
	total := 0.0
	if len(b.Ptr) >= 9 && b.Ptr[0] > 0 {
		f.Set("beh.ptr_samples", b.Ptr[0])
		f.Set("beh.ptr_path_len", b.Ptr[1])
		f.Set("beh.ptr_straightness", b.Ptr[2])
		f.Set("beh.ptr_speed_cv", b.Ptr[3])
		f.Set("beh.ptr_dir_changes", b.Ptr[4])
		f.Set("beh.ptr_accel_flips", b.Ptr[5])
		f.Set("beh.ptr_interval_cv", b.Ptr[6])
		f.Set("beh.ptr_collinear_frac", b.Ptr[7])
		f.Set("beh.untrusted_frac", b.Ptr[8])
		total += b.Ptr[0]
	}
	if len(b.Clk) >= 5 && b.Clk[0] > 0 {
		f.Set("beh.click_count", b.Clk[0])
		f.Set("beh.click_dur_mean", b.Clk[1])
		f.Set("beh.click_dur_cv", b.Clk[2])
		f.Set("beh.click_center_frac", b.Clk[3])
		f.SetBool("beh.click_no_move", b.Clk[4] == 1)
		total += b.Clk[0]
	}
	if len(b.Key) >= 7 && b.Key[0] > 0 {
		f.Set("beh.key_count", b.Key[0])
		f.Set("beh.key_hold_mean", b.Key[1])
		f.Set("beh.key_hold_cv", b.Key[2])
		f.Set("beh.key_interval_cv", b.Key[3])
		f.Set("beh.key_backspace_frac", b.Key[4])
		total += b.Key[0]
	}
	if len(b.Key) >= 7 {
		if b.Key[5] >= 0 {
			f.Set("beh.input_no_key_frac", b.Key[5])
		}
		f.Set("beh.paste_count", b.Key[6])
	}
	if len(b.Scr) >= 2 {
		f.Set("beh.scroll_count", b.Scr[0])
		f.Set("beh.wheel_class", b.Scr[1])
		total += b.Scr[0]
	}
	if len(b.Foc) >= 4 {
		f.SetBool("beh.focus_start", b.Foc[0] == 1)
		f.SetBool("beh.focus_submit", b.Foc[1] == 1)
		f.Set("beh.visibility_changes", b.Foc[2])
		f.SetBool("beh.hidden_at_submit", b.Foc[3] == 1)
	}
	if len(b.Raf) >= 2 && b.Raf[0] > 0 {
		f.Set("beh.raf_median", b.Raf[0])
		f.Set("beh.raf_cv", b.Raf[1])
	}
	f.Set("beh.total_events", total)
}

// Classified holds request-scoped derived values. Never persisted raw.
type Classified struct {
	UAFamily    string
	UAMajor     int
	OSFamily    string
	Mobile      bool
	TZUTC       bool
	TZCountry   string
	LangPrimary string
	Langs       []string
	GPUClass    string
	CanvasHash  string
	GLHash      string
	FontMask    string
	ScreenKey   string
	HCBucket    int
}

func classify(p *Payload) Classified {
	ua := p.FP.UA
	c := Classified{}
	c.UAFamily, c.UAMajor = uaFamily(ua)
	c.OSFamily = osFamily(ua)
	c.Mobile = strings.Contains(ua, "Mobile") || strings.Contains(ua, "Android") && !strings.Contains(ua, "Tablet")
	if c.OSFamily == "ios" {
		c.Mobile = true
	}
	tz := p.FP.TZ
	c.TZUTC = tz == "UTC" || tz == "Etc/UTC" || tz == "Etc/GMT" || tz == "GMT"
	c.TZCountry = tzCountry[tz]
	for _, l := range p.FP.Lang {
		c.Langs = append(c.Langs, strings.ToLower(l))
	}
	if len(c.Langs) > 0 {
		c.LangPrimary = strings.SplitN(c.Langs[0], "-", 2)[0]
	}
	c.GPUClass = gpuClass(p.FP.GL, p.FP.CV.B)
	c.CanvasHash = p.FP.CV.H
	if p.FP.GL != nil {
		c.GLHash = p.FP.GL[0] + "|" + p.FP.GL[1]
	}
	c.FontMask = p.FP.FN
	if len(p.FP.Scr) >= 2 {
		c.ScreenKey = strconv.Itoa(int(p.FP.Scr[0])/160) + "x" + strconv.Itoa(int(p.FP.Scr[1])/160) + "@" + strconv.Itoa(int(math.Round(at(p.FP.Scr, 5)/0.25)))
	}
	c.HCBucket = int(scoring.BucketIndex(float64(p.FP.HC), 3, 5, 9, 17))
	return c
}

// UAFamily parses a browser family and major version from a UA string.
// Exported for signals/net which applies it to the header.
func UAFamily(ua string) (string, int) { return uaFamily(ua) }

func uaFamily(ua string) (string, int) {
	if ua == "" {
		return "none", 0
	}
	type rule struct{ token, family string }
	// Order matters: most specific first.
	for _, r := range []rule{
		{"EdgiOS/", "edge"}, {"Edg/", "edge"}, {"OPR/", "opera"}, {"SamsungBrowser/", "samsung"},
		{"FxiOS/", "firefox"}, {"Firefox/", "firefox"}, {"CriOS/", "chrome"},
		{"HeadlessChrome/", "chrome"}, {"Chrome/", "chrome"}, {"Version/", "safari"},
	} {
		if i := strings.Index(ua, r.token); i >= 0 {
			if r.family == "safari" && !strings.Contains(ua, "Safari/") {
				continue
			}
			rest := ua[i+len(r.token):]
			end := strings.IndexAny(rest, ". ;)")
			if end < 0 {
				end = len(rest)
			}
			major, _ := strconv.Atoi(rest[:end])
			return r.family, major
		}
	}
	lower := strings.ToLower(ua)
	switch {
	case strings.HasPrefix(lower, "curl/"):
		return "curl", 0
	case strings.Contains(lower, "python"):
		return "python", 0
	case strings.HasPrefix(lower, "go-http-client"):
		return "go", 0
	case strings.Contains(lower, "java/") || strings.Contains(lower, "okhttp"):
		return "java", 0
	case strings.HasPrefix(lower, "node") || strings.Contains(lower, "axios") || strings.Contains(lower, "undici"):
		return "node", 0
	}
	return "other", 0
}

// OSFamily is exported for signals/net.
func OSFamily(ua string) string { return osFamily(ua) }

func osFamily(ua string) string {
	switch {
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPad"), strings.Contains(ua, "iPod"):
		return "ios"
	case strings.Contains(ua, "Android"):
		return "android"
	case strings.Contains(ua, "CrOS"):
		return "chromeos"
	case strings.Contains(ua, "Windows"):
		return "windows"
	case strings.Contains(ua, "Mac OS X"), strings.Contains(ua, "Macintosh"):
		return "macos"
	case strings.Contains(ua, "Linux"), strings.Contains(ua, "X11"):
		return "linux"
	}
	return "other"
}

func gpuClass(gl []string, canvasBlocked bool) string {
	if gl == nil {
		return "blocked"
	}
	r := strings.ToLower(gl[0] + " " + gl[1])
	switch {
	case strings.TrimSpace(r) == "":
		return "none"
	case strings.Contains(r, "swiftshader"), strings.Contains(r, "llvmpipe"),
		strings.Contains(r, "softpipe"), strings.Contains(r, "mesa offscreen"),
		strings.Contains(r, "microsoft basic render"):
		return "software"
	}
	return "hardware"
}

func gpuOSMismatch(gl []string, os string) bool {
	if gl == nil {
		return false
	}
	r := strings.ToLower(gl[1])
	apple := strings.Contains(r, "apple m") || strings.Contains(r, "apple gpu")
	switch os {
	case "windows", "android", "linux":
		return apple
	case "macos", "ios":
		return strings.Contains(r, "direct3d") || strings.Contains(r, "adreno") || strings.Contains(r, "mali")
	}
	return false
}

func uadMismatch(u *UAD, c Classified) bool {
	if u.Mobile != c.Mobile && c.OSFamily != "android" {
		return true
	}
	p := strings.ToLower(u.Platform)
	want := map[string]string{"windows": "windows", "macos": "macos", "android": "android", "linux": "linux", "chromeos": "chrome os"}[c.OSFamily]
	if p != "" && want != "" && p != want {
		return true
	}
	return false
}

// featMismatch compares the feature-probe bitmask with what the claimed
// browser version must support. Probe bit order is defined in
// web/snippet/src/collect/fp.ts (FEATURE_PROBES) and mirrored in probes.
func featMismatch(family string, major int, b64 string) int {
	if b64 == "" || major == 0 {
		return 0
	}
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return 0
	}
	has := func(i int) bool {
		if i/8 >= len(raw) {
			return false
		}
		return raw[i/8]&(1<<(i%8)) != 0
	}
	n := 0
	for i, pr := range probes {
		since := pr.since[family]
		if since == 0 {
			continue
		}
		expect := major >= since
		if expect != has(i) {
			n++
		}
	}
	return n
}

// probes lists feature probes and the first major version shipping them per
// family. Must stay in the same order as FEATURE_PROBES in the snippet.
var probes = []struct {
	name  string
	since map[string]int
}{
	{"Array.prototype.at", map[string]int{"chrome": 92, "edge": 92, "firefox": 90, "safari": 15}},
	{"Object.hasOwn", map[string]int{"chrome": 93, "edge": 93, "firefox": 92, "safari": 15}},
	{"structuredClone", map[string]int{"chrome": 98, "edge": 98, "firefox": 94, "safari": 15}},
	{"Array.prototype.findLast", map[string]int{"chrome": 97, "edge": 97, "firefox": 104, "safari": 15}},
	{"navigator.userAgentData", map[string]int{"chrome": 90, "edge": 90}},
	{"Array.prototype.toSorted", map[string]int{"chrome": 110, "edge": 110, "firefox": 115, "safari": 16}},
	{"URL.canParse", map[string]int{"chrome": 120, "edge": 120, "firefox": 115, "safari": 17}},
	{"Promise.withResolvers", map[string]int{"chrome": 119, "edge": 119, "firefox": 121, "safari": 17}},
	{"Object.groupBy", map[string]int{"chrome": 117, "edge": 117, "firefox": 119, "safari": 17}},
	{"Set.prototype.union", map[string]int{"chrome": 122, "edge": 122, "firefox": 127, "safari": 17}},
	{"CSS.registerProperty", map[string]int{"chrome": 78, "edge": 79, "firefox": 128, "safari": 16}},
	{"Iterator.prototype.map", map[string]int{"chrome": 122, "edge": 122, "firefox": 131, "safari": 18}},
}

// Font mask bits mirror FONT_PROBES in web/snippet/src/collect/fonts.ts.
const (
	fontWindowsMask = 0x3F       // bits 0-5: Segoe UI, Calibri, Cambria, Consolas, Tahoma, Segoe UI Emoji
	fontMacMask     = 0x3F << 6  // bits 6-11: Helvetica Neue, Menlo, SF Pro, Apple Color Emoji, Avenir, Geneva
	fontAndroidMask = 0x0F << 12 // bits 12-15: Roboto, Noto Color Emoji, Droid Sans, Noto Sans
	fontLinuxMask   = 0x0F << 16 // bits 16-19: DejaVu Sans, Liberation Sans, Ubuntu, Cantarell
)

func fontOSClass(b64 string) string {
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return "other"
	}
	var m uint64
	for i, b := range raw {
		m |= uint64(b) << (8 * i)
	}
	win := m&fontWindowsMask != 0
	mac := m&fontMacMask != 0
	and := m&fontAndroidMask != 0
	lin := m&fontLinuxMask != 0
	count := 0
	for _, x := range []bool{win, mac, and, lin} {
		if x {
			count++
		}
	}
	switch {
	case m == 0:
		return "none"
	case count > 1 && !(and && lin):
		return "mixed"
	case win:
		return "windows"
	case mac:
		return "macos"
	case and && !lin:
		return "android"
	case lin && m&(1<<18|1<<19) != 0:
		return "linux-desktop"
	case lin:
		return "linux-bare"
	}
	return "other"
}

func fontMismatch(cls, os string) bool {
	switch cls {
	case "none", "other", "mixed":
		return false
	case "linux-bare":
		return os == "windows" || os == "macos" || os == "ios"
	case "windows":
		return os == "macos" || os == "ios" || os == "android"
	case "macos":
		return os == "windows" || os == "android"
	case "android":
		return os == "windows" || os == "macos" || os == "ios"
	case "linux-desktop":
		return os == "windows" || os == "macos" || os == "ios"
	}
	return false
}
