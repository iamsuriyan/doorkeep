// Package scoring defines the feature vector contract shared by payload
// normalisation, the rules layer, the model layer, storage and documentation.
//
// features.go is the single source of truth for feature keys. Every key is
// registered once with its kind, group and description; `go generate` renders
// docs/reference/features.md and a TypeScript const file for the dashboard
// from this registry so the three never drift.
//
// Design rule (docs/design/v1.md section 1.1): a missing feature is "unknown",
// never "suspicious". Numeric features use NaN for missing; categorical
// features use the empty string. Both layers treat missing as neutral.
package scoring

import (
	"math"
	"sort"
	"strings"
)

// Kind describes how a feature value is interpreted.
type Kind uint8

const (
	// KindBool is 0 or 1.
	KindBool Kind = iota + 1
	// KindBucket is a small non-negative ordinal (bucket index).
	KindBucket
	// KindFloat is a bounded float, clamped to [Min, Max].
	KindFloat
	// KindCount is a non-negative integer count (clamped to Max).
	KindCount
	// KindCat is a categorical string value (stored separately).
	KindCat
)

func (k Kind) String() string {
	switch k {
	case KindBool:
		return "bool"
	case KindBucket:
		return "bucket"
	case KindFloat:
		return "float"
	case KindCount:
		return "count"
	case KindCat:
		return "cat"
	}
	return "unknown"
}

// Group is the dotted prefix a feature lives under. Rule expressions address
// features as `<group>.<name>`, e.g. `auto.wd` or `beh.ptr_straightness`.
type Group string

const (
	GroupProfile   Group = "prof" // privacy-browser profile hints (informational)
	GroupAuto      Group = "auto" // automation markers
	GroupFP        Group = "fp"   // fingerprint consistency
	GroupBehaviour Group = "beh"  // behaviour aggregates
	GroupEnv       Group = "env"  // environment
	GroupTiming    Group = "t"    // timeline / timing truth
	GroupNet       Group = "net"  // server-derived network and header signals
	GroupVelocity  Group = "vel"  // rate and velocity counters
)

// Def is the registry entry for one feature.
type Def struct {
	Group Group
	Name  string
	Kind  Kind
	// Min and Max bound KindFloat/KindCount values. For KindBucket, Max is the
	// highest bucket index. Ignored for KindBool and KindCat.
	Min, Max float64
	// Buckets, for KindBucket, documents the bucket edges or labels.
	Buckets []string
	// Values, for KindCat, documents the allowed values ("" is unknown).
	Values []string
	// Desc is a one-line human description rendered in docs and the dashboard.
	Desc string
	// Model controls whether the model layer may use this feature. Features
	// that must never influence risk on their own (accessibility hints,
	// privacy signals such as DNT/GPC) are registered with Model=false.
	Model bool
}

// Key returns the dotted key, e.g. "auto.wd".
func (d Def) Key() string { return string(d.Group) + "." + d.Name }

var (
	registry   = map[string]Def{}
	registryBy []Def
)

func reg(d Def) {
	k := d.Key()
	if _, dup := registry[k]; dup {
		panic("scoring: duplicate feature " + k)
	}
	if d.Kind == 0 {
		panic("scoring: feature without kind " + k)
	}
	registry[k] = d
	registryBy = append(registryBy, d)
}

// Registry returns all feature definitions in registration order.
func Registry() []Def {
	out := make([]Def, len(registryBy))
	copy(out, registryBy)
	return out
}

// Lookup returns the definition for a dotted key.
func Lookup(key string) (Def, bool) {
	d, ok := registry[key]
	return d, ok
}

// Features is one event's feature vector. Numeric features live in Num
// (NaN = unknown), categorical features in Cat ("" = unknown). Keys are the
// dotted registry keys. Features is the only thing persisted beyond
// aggregates; it is bucketed by construction (section 6).
type Features struct {
	Num map[string]float64
	Cat map[string]string
}

// NewFeatures returns an empty vector.
func NewFeatures() Features {
	return Features{Num: map[string]float64{}, Cat: map[string]string{}}
}

// Set stores a numeric feature after validating it against the registry:
// unknown keys panic (programming error), out-of-range values are clamped,
// bools are coerced to 0/1 and NaN is dropped (unknown).
func (f Features) Set(key string, v float64) {
	d, ok := registry[key]
	if !ok {
		panic("scoring: unregistered feature " + key)
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		delete(f.Num, key)
		return
	}
	switch d.Kind {
	case KindBool:
		if v != 0 {
			v = 1
		}
	case KindBucket, KindCount:
		v = math.Round(v)
		if v < 0 {
			v = 0
		}
		if d.Max > 0 && v > d.Max {
			v = d.Max
		}
	case KindFloat:
		if v < d.Min {
			v = d.Min
		}
		if d.Max > d.Min && v > d.Max {
			v = d.Max
		}
	case KindCat:
		panic("scoring: Set called for categorical feature " + key)
	}
	f.Num[key] = v
}

// SetBool is a convenience for KindBool features.
func (f Features) SetBool(key string, b bool) {
	if b {
		f.Set(key, 1)
	} else {
		f.Set(key, 0)
	}
}

// SetCat stores a categorical feature. Values not in the registered list are
// normalised to "other" so free-form input never leaks into storage.
func (f Features) SetCat(key, v string) {
	d, ok := registry[key]
	if !ok || d.Kind != KindCat {
		panic("scoring: unregistered or non-categorical feature " + key)
	}
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		delete(f.Cat, key)
		return
	}
	if len(d.Values) > 0 {
		found := false
		for _, allowed := range d.Values {
			if allowed == v {
				found = true
				break
			}
		}
		if !found {
			v = "other"
		}
	}
	f.Cat[key] = v
}

// Get returns a numeric feature or NaN when unknown.
func (f Features) Get(key string) float64 {
	if v, ok := f.Num[key]; ok {
		return v
	}
	return math.NaN()
}

// Has reports whether a numeric or categorical feature is known.
func (f Features) Has(key string) bool {
	if _, ok := f.Num[key]; ok {
		return true
	}
	_, ok := f.Cat[key]
	return ok
}

// Env builds the nested map that rule expressions evaluate against:
// {"auto": {"wd": 1, ...}, "fp": {...}, ...}. Unknown numeric features are
// present as NaN so expressions like `auto.wd == 1` are false rather than
// errors; unknown categorical features are "".
func (f Features) Env() map[string]any {
	env := map[string]any{}
	for _, d := range registryBy {
		g, ok := env[string(d.Group)].(map[string]any)
		if !ok {
			g = map[string]any{}
			env[string(d.Group)] = g
		}
		if d.Kind == KindCat {
			g[d.Name] = f.Cat[d.Key()]
			continue
		}
		if v, ok := f.Num[d.Key()]; ok {
			g[d.Name] = v
		} else {
			g[d.Name] = math.NaN()
		}
	}
	return env
}

// Keys returns the sorted list of known keys (numeric then categorical).
func (f Features) Keys() []string {
	keys := make([]string, 0, len(f.Num)+len(f.Cat))
	for k := range f.Num {
		keys = append(keys, k)
	}
	for k := range f.Cat {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Bucket helpers shared by normalisation code.

// BucketIndex returns the index of the first edge greater than v, i.e. the
// bucket v falls in for ascending edges; len(edges) when v >= last edge.
func BucketIndex(v float64, edges ...float64) float64 {
	for i, e := range edges {
		if v < e {
			return float64(i)
		}
	}
	return float64(len(edges))
}

func init() {
	// ---- prof: privacy-browser profile hints. Informational, never risk. ----
	reg(Def{Group: GroupProfile, Name: "rfp", Kind: KindBool, Desc: "Firefox resistFingerprinting or Tor Browser detected; fingerprint-consistency rules are gated off", Model: false})
	reg(Def{Group: GroupProfile, Name: "brave", Kind: KindBool, Desc: "Brave Shields farbling detected; canvas/audio/WebGL consistency rules are gated off", Model: false})
	reg(Def{Group: GroupProfile, Name: "tor", Kind: KindBool, Desc: "Tor Browser specifically (subset of rfp)", Model: false})
	reg(Def{Group: GroupProfile, Name: "dnt", Kind: KindBool, Desc: "Do Not Track or Global Privacy Control set; never a risk signal", Model: false})
	reg(Def{Group: GroupProfile, Name: "forced_colors", Kind: KindBool, Desc: "forced-colors: active (accessibility hint); never a risk signal", Model: false})

	// ---- auto: automation markers (section 1.2 A) ----
	reg(Def{Group: GroupAuto, Name: "wd", Kind: KindBucket, Max: 2, Buckets: []string{"false", "true", "undefined/missing"}, Desc: "navigator.webdriver state", Model: true})
	reg(Def{Group: GroupAuto, Name: "wd_tamper", Kind: KindBool, Desc: "navigator.webdriver getter tampered (missing descriptor, non-native toString, realm mismatch)", Model: true})
	reg(Def{Group: GroupAuto, Name: "cdp", Kind: KindBool, Desc: "CDP Runtime.enable artefact observed (stack/console serialisation probe fired)", Model: true})
	reg(Def{Group: GroupAuto, Name: "leaks", Kind: KindCount, Max: 32, Desc: "Count of known automation globals present (cdc_, __playwright, __puppeteer, ...)", Model: true})
	reg(Def{Group: GroupAuto, Name: "headless_ua", Kind: KindBool, Desc: "HeadlessChrome in UA or userAgentData brands", Model: true})
	reg(Def{Group: GroupAuto, Name: "outer_zero", Kind: KindBool, Desc: "outerWidth or outerHeight is 0", Model: true})
	reg(Def{Group: GroupAuto, Name: "outer_eq_inner", Kind: KindBool, Desc: "outer == inner on a desktop UA with no fullscreen element", Model: true})
	reg(Def{Group: GroupAuto, Name: "default_viewport", Kind: KindBool, Desc: "800x600 viewport at DPR 1 (framework default)", Model: true})
	reg(Def{Group: GroupAuto, Name: "plugins", Kind: KindCount, Max: 16, Desc: "navigator.plugins.length", Model: true})
	reg(Def{Group: GroupAuto, Name: "plugins_shape", Kind: KindBucket, Max: 3, Buckets: []string{"native-expected", "empty", "non-native-prototype", "inconsistent"}, Desc: "PluginArray shape class", Model: true})
	reg(Def{Group: GroupAuto, Name: "lang_count", Kind: KindCount, Max: 8, Desc: "navigator.languages length", Model: true})
	reg(Def{Group: GroupAuto, Name: "chrome_obj", Kind: KindBucket, Max: 3, Buckets: []string{"n/a (non-chromium UA)", "present-native", "missing", "present-fake"}, Desc: "window.chrome object shape class", Model: true})
	reg(Def{Group: GroupAuto, Name: "notif_contradiction", Kind: KindBool, Desc: "Notification.permission denied while permissions.query says prompt", Model: true})
	reg(Def{Group: GroupAuto, Name: "conn_rtt_zero", Kind: KindBool, Desc: "navigator.connection.rtt === 0 (emulated network)", Model: true})
	reg(Def{Group: GroupAuto, Name: "voices", Kind: KindBucket, Max: 3, Buckets: []string{"n/a", "0", "1-5", "6+"}, Desc: "speechSynthesis voices count bucket", Model: true})
	reg(Def{Group: GroupAuto, Name: "eng", Kind: KindCat, Values: []string{"v8", "spidermonkey", "jsc", "other"}, Desc: "JS engine class from error-message and eval probes", Model: true})
	reg(Def{Group: GroupAuto, Name: "non_native_apis", Kind: KindCount, Max: 8, Desc: "Count of core APIs (fetch, Promise, crypto.subtle, TextEncoder, ...) whose toString is not native code", Model: true})

	// ---- fp: fingerprint consistency (section 1.2 B) ----
	reg(Def{Group: GroupFP, Name: "ua_family", Kind: KindCat, Values: []string{"chrome", "edge", "firefox", "safari", "opera", "samsung", "brave", "other", "none"}, Desc: "Browser family parsed from navigator.userAgent", Model: true})
	reg(Def{Group: GroupFP, Name: "ua_major", Kind: KindCount, Max: 999, Desc: "Browser major version", Model: true})
	reg(Def{Group: GroupFP, Name: "os_family", Kind: KindCat, Values: []string{"windows", "macos", "ios", "android", "linux", "chromeos", "other"}, Desc: "OS family parsed from navigator.userAgent", Model: true})
	reg(Def{Group: GroupFP, Name: "ua_mobile", Kind: KindBool, Desc: "UA claims a mobile device", Model: true})
	reg(Def{Group: GroupFP, Name: "feat_mismatch", Kind: KindCount, Max: 32, Desc: "Count of feature probes inconsistent with the claimed browser major version", Model: true})
	reg(Def{Group: GroupFP, Name: "uad_mismatch", Kind: KindBool, Desc: "navigator.userAgentData disagrees with the UA string", Model: true})
	reg(Def{Group: GroupFP, Name: "mobile_no_touch", Kind: KindBool, Desc: "Mobile UA with maxTouchPoints 0 and wide screen", Model: true})
	reg(Def{Group: GroupFP, Name: "desktop_coarse_pointer", Kind: KindBool, Desc: "Desktop Chrome UA with coarse pointer and no touch points (device emulation)", Model: true})
	reg(Def{Group: GroupFP, Name: "screen_w_bucket", Kind: KindBucket, Max: 20, Desc: "screen.width in 160 px buckets", Model: true})
	reg(Def{Group: GroupFP, Name: "dpr_bucket", Kind: KindBucket, Max: 16, Desc: "devicePixelRatio in 0.25 steps", Model: true})
	reg(Def{Group: GroupFP, Name: "avail_eq_screen", Kind: KindBool, Desc: "availHeight == height on a claimed Windows desktop (no taskbar)", Model: true})
	reg(Def{Group: GroupFP, Name: "tz_offset_mismatch", Kind: KindBool, Desc: "Intl timezone id disagrees with Date.getTimezoneOffset", Model: true})
	reg(Def{Group: GroupFP, Name: "tz_utc", Kind: KindBool, Desc: "Timezone is UTC/Etc", Model: true})
	reg(Def{Group: GroupFP, Name: "tz_country", Kind: KindCat, Desc: "Country derived from the timezone id (ISO 3166-1 alpha-2, lowercase)", Model: true})
	reg(Def{Group: GroupFP, Name: "lang_primary", Kind: KindCat, Desc: "Primary language subtag from navigator.languages (lowercase)", Model: true})
	reg(Def{Group: GroupFP, Name: "gpu_class", Kind: KindCat, Values: []string{"hardware", "software", "blocked", "none", "other"}, Desc: "WebGL renderer class (software = SwiftShader/llvmpipe/Mesa offscreen)", Model: true})
	reg(Def{Group: GroupFP, Name: "gpu_os_mismatch", Kind: KindBool, Desc: "WebGL renderer vendor family impossible for the claimed OS", Model: true})
	reg(Def{Group: GroupFP, Name: "canvas_blocked", Kind: KindBool, Desc: "Canvas returned blank (blocked or RFP)", Model: true})
	reg(Def{Group: GroupFP, Name: "canvas_known_headless", Kind: KindBool, Desc: "Canvas hash matches a known software-renderer hash", Model: true})
	reg(Def{Group: GroupFP, Name: "audio_present", Kind: KindBool, Desc: "Audio fingerprint computed", Model: true})
	reg(Def{Group: GroupFP, Name: "font_os_class", Kind: KindCat, Values: []string{"windows", "macos", "android", "linux-desktop", "linux-bare", "mixed", "none", "other"}, Desc: "OS class inferred from the font presence bitmask", Model: true})
	reg(Def{Group: GroupFP, Name: "font_os_mismatch", Kind: KindBool, Desc: "Font OS class contradicts the claimed OS", Model: true})
	reg(Def{Group: GroupFP, Name: "hc_bucket", Kind: KindBucket, Max: 4, Buckets: []string{"1-2", "3-4", "5-8", "9-16", "17+"}, Desc: "hardwareConcurrency bucket", Model: true})
	reg(Def{Group: GroupFP, Name: "dm_bucket", Kind: KindBucket, Max: 3, Buckets: []string{"<=2", "4", "8", ">=16"}, Desc: "deviceMemory bucket (Chromium only)", Model: true})
	reg(Def{Group: GroupFP, Name: "touch_points", Kind: KindCount, Max: 10, Desc: "navigator.maxTouchPoints", Model: true})
	reg(Def{Group: GroupFP, Name: "pointer_class", Kind: KindBucket, Max: 3, Buckets: []string{"none", "fine", "coarse", "both"}, Desc: "pointer/any-pointer media query class", Model: true})
	reg(Def{Group: GroupFP, Name: "color_scheme_dark", Kind: KindBool, Desc: "prefers-color-scheme: dark", Model: true})
	reg(Def{Group: GroupFP, Name: "reduced_motion", Kind: KindBool, Desc: "prefers-reduced-motion: reduce", Model: false})

	// ---- beh: behaviour aggregates (section 1.2 C). Absent = neutral. ----
	reg(Def{Group: GroupBehaviour, Name: "total_events", Kind: KindCount, Max: 100000, Desc: "Total trusted input events observed", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "ptr_samples", Kind: KindCount, Max: 100000, Desc: "Pointer move samples", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "ptr_path_len", Kind: KindFloat, Max: 1e7, Desc: "Total pointer path length (px)", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "ptr_straightness", Kind: KindFloat, Max: 1, Desc: "Displacement / path length (1 = perfectly straight)", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "ptr_speed_cv", Kind: KindFloat, Max: 10, Desc: "Coefficient of variation of pointer speed", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "ptr_dir_changes", Kind: KindCount, Max: 100000, Desc: "Direction changes along the pointer path", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "ptr_accel_flips", Kind: KindCount, Max: 100000, Desc: "Acceleration sign changes", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "ptr_interval_cv", Kind: KindFloat, Max: 10, Desc: "Coefficient of variation of inter-sample intervals", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "ptr_collinear_frac", Kind: KindFloat, Max: 1, Desc: "Fraction of consecutive triples that are exactly collinear", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "untrusted_frac", Kind: KindFloat, Max: 1, Desc: "Fraction of input events with isTrusted === false", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "click_count", Kind: KindCount, Max: 10000, Desc: "Pointer down/up pairs", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "click_dur_mean", Kind: KindFloat, Max: 10000, Desc: "Mean press duration (ms)", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "click_dur_cv", Kind: KindFloat, Max: 10, Desc: "CV of press duration", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "click_center_frac", Kind: KindFloat, Max: 1, Desc: "Fraction of clicks landing within 1 px of the element centre", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "click_no_move", Kind: KindBool, Desc: "A click occurred with no pointer movement observed beforehand", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "key_count", Kind: KindCount, Max: 100000, Desc: "Key down events", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "key_hold_mean", Kind: KindFloat, Max: 10000, Desc: "Mean keydown to keyup (ms)", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "key_hold_cv", Kind: KindFloat, Max: 10, Desc: "CV of key hold time", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "key_interval_cv", Kind: KindFloat, Max: 10, Desc: "CV of inter-key interval", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "key_backspace_frac", Kind: KindFloat, Max: 1, Desc: "Backspace share of key events", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "input_no_key_frac", Kind: KindFloat, Max: 1, Desc: "Fraction of changed fields that received input without any keydown (fill/autofill)", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "paste_count", Kind: KindCount, Max: 1000, Desc: "Paste events", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "scroll_count", Kind: KindCount, Max: 100000, Desc: "Scroll/wheel events", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "wheel_class", Kind: KindBucket, Max: 3, Buckets: []string{"none", "mouse (120 multiples)", "trackpad (small floats)", "exact-round-other"}, Desc: "Wheel delta quantisation class", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "focus_start", Kind: KindBool, Desc: "document.hasFocus() at snippet start", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "focus_submit", Kind: KindBool, Desc: "document.hasFocus() at submit", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "visibility_changes", Kind: KindCount, Max: 1000, Desc: "visibilitychange/blur/focus events", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "hidden_at_submit", Kind: KindBool, Desc: "document.visibilityState hidden at submit", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "raf_median", Kind: KindFloat, Max: 1000, Desc: "Median requestAnimationFrame interval (ms)", Model: true})
	reg(Def{Group: GroupBehaviour, Name: "raf_cv", Kind: KindFloat, Max: 10, Desc: "CV of rAF interval (0 = synthetic flat clock)", Model: true})

	// ---- env: environment (section 1.2 D) ----
	reg(Def{Group: GroupEnv, Name: "perm_all_prompt", Kind: KindBool, Desc: "Every queried permission is in prompt state (fresh context)", Model: true})
	reg(Def{Group: GroupEnv, Name: "perm_granted_count", Kind: KindCount, Max: 8, Desc: "Permissions in granted state", Model: true})
	reg(Def{Group: GroupEnv, Name: "storage_ok", Kind: KindBool, Desc: "localStorage write/read round-trip succeeded", Model: true})
	reg(Def{Group: GroupEnv, Name: "storage_throws", Kind: KindBool, Desc: "A storage API threw", Model: true})
	reg(Def{Group: GroupEnv, Name: "cookies", Kind: KindBool, Desc: "navigator.cookieEnabled", Model: true})
	reg(Def{Group: GroupEnv, Name: "quota_bucket", Kind: KindBucket, Max: 3, Buckets: []string{"n/a", "<1GB (incognito-like)", "1-10GB", ">10GB"}, Desc: "storage.estimate().quota bucket", Model: true})
	reg(Def{Group: GroupEnv, Name: "timer_precision", Kind: KindBucket, Max: 2, Buckets: []string{"fine", "coarse (RFP 100ms)", "unknown"}, Desc: "performance.now precision class", Model: true})
	reg(Def{Group: GroupEnv, Name: "dom_ready_bucket", Kind: KindBucket, Max: 4, Buckets: []string{"<50ms", "50-200", "200-1000", "1-5s", ">5s"}, Desc: "domContentLoadedEventEnd - fetchStart", Model: true})
	reg(Def{Group: GroupEnv, Name: "resources_bucket", Kind: KindBucket, Max: 3, Buckets: []string{"0", "1-5", "6-30", "31+"}, Desc: "Resource timing entry count", Model: true})
	reg(Def{Group: GroupEnv, Name: "snippet_version", Kind: KindCount, Max: 100000, Desc: "Snippet schema/build version", Model: false})

	// ---- t: timeline and timing truth ----
	reg(Def{Group: GroupTiming, Name: "elapsed_s", Kind: KindFloat, Max: 3600, Desc: "Server-measured seconds from nonce issue to submit", Model: true})
	reg(Def{Group: GroupTiming, Name: "client_elapsed_s", Kind: KindFloat, Max: 3600, Desc: "Client-reported seconds from init to submit", Model: true})
	reg(Def{Group: GroupTiming, Name: "elapsed_mismatch", Kind: KindBool, Desc: "Client and server elapsed disagree by more than 1 s", Model: true})
	reg(Def{Group: GroupTiming, Name: "first_interaction_s", Kind: KindFloat, Max: 3600, Desc: "Seconds from init to first trusted interaction (NaN if none)", Model: true})
	reg(Def{Group: GroupTiming, Name: "clock_skew_s", Kind: KindFloat, Min: -1e6, Max: 1e6, Desc: "Client Date.now() minus server time at issue (s)", Model: true})
	reg(Def{Group: GroupTiming, Name: "collect_too_fast", Kind: KindBool, Desc: "Deferred modules reported complete implausibly fast", Model: true})

	// ---- net: server-derived (section 3). Filled by signals/net, tlsfp, h2fp, ipintel. ----
	reg(Def{Group: GroupNet, Name: "ua_hdr_family", Kind: KindCat, Values: []string{"chrome", "edge", "firefox", "safari", "opera", "samsung", "brave", "curl", "python", "go", "java", "node", "other", "none"}, Desc: "Browser family parsed from the User-Agent header", Model: true})
	reg(Def{Group: GroupNet, Name: "ua_hdr_js_mismatch", Kind: KindBool, Desc: "User-Agent header differs from navigator.userAgent", Model: true})
	reg(Def{Group: GroupNet, Name: "ch_missing", Kind: KindBool, Desc: "Chromium UA without Sec-CH-UA headers", Model: true})
	reg(Def{Group: GroupNet, Name: "ch_unexpected", Kind: KindBool, Desc: "Non-Chromium UA sending Sec-CH-UA headers", Model: true})
	reg(Def{Group: GroupNet, Name: "ch_mismatch", Kind: KindBool, Desc: "Sec-CH-UA disagrees with UA or userAgentData", Model: true})
	reg(Def{Group: GroupNet, Name: "fetch_metadata_missing", Kind: KindBool, Desc: "Sec-Fetch-* headers absent on a modern browser UA", Model: true})
	reg(Def{Group: GroupNet, Name: "accept_lang_mismatch", Kind: KindBool, Desc: "Accept-Language primary tag not in navigator.languages", Model: true})
	reg(Def{Group: GroupNet, Name: "accept_lang_missing", Kind: KindBool, Desc: "Accept-Language header absent", Model: true})
	reg(Def{Group: GroupNet, Name: "accept_wrong", Kind: KindBool, Desc: "Accept header is a navigation Accept on an XHR endpoint", Model: true})
	reg(Def{Group: GroupNet, Name: "engine_mismatch", Kind: KindBool, Desc: "JS engine class contradicts the UA family", Model: true})
	reg(Def{Group: GroupNet, Name: "http_version", Kind: KindBucket, Max: 3, Buckets: []string{"unknown", "1.1", "2", "3"}, Desc: "HTTP protocol version observed", Model: true})
	reg(Def{Group: GroupNet, Name: "http1_on_h2", Kind: KindBool, Desc: "Modern browser UA used HTTP/1.1 although h2 was offered", Model: true})
	reg(Def{Group: GroupNet, Name: "tls_available", Kind: KindBool, Desc: "TLS fingerprint was observable (doorkeep terminated TLS or trusted proxy forwarded it)", Model: false})
	reg(Def{Group: GroupNet, Name: "tls_class", Kind: KindCat, Values: []string{"browser", "openssl", "go", "node", "java", "okhttp", "other", "none"}, Desc: "JA4 client class (TLS separates browsers from libraries, not browsers from each other)", Model: true})
	reg(Def{Group: GroupNet, Name: "tls_ua_mismatch", Kind: KindBool, Desc: "JA4 class contradicts the UA family", Model: true})
	reg(Def{Group: GroupNet, Name: "h2_class", Kind: KindCat, Values: []string{"chrome", "firefox", "safari", "curl", "go", "other", "none"}, Desc: "HTTP/2 fingerprint class", Model: true})
	reg(Def{Group: GroupNet, Name: "h2_ua_mismatch", Kind: KindBool, Desc: "HTTP/2 class contradicts the UA family", Model: true})
	reg(Def{Group: GroupNet, Name: "asn_class", Kind: KindCat, Values: []string{"hosting", "isp", "mobile", "edu", "gov", "unknown"}, Desc: "ASN class from ipdata", Model: true})
	reg(Def{Group: GroupNet, Name: "ip_tor", Kind: KindBool, Desc: "Source IP is a Tor exit", Model: true})
	reg(Def{Group: GroupNet, Name: "ip_drop", Kind: KindBool, Desc: "Source IP in Spamhaus DROP/EDROP", Model: true})
	reg(Def{Group: GroupNet, Name: "ip_known_crawler", Kind: KindBool, Desc: "Source IP belongs to a verified crawler publisher", Model: true})
	reg(Def{Group: GroupNet, Name: "ip_country", Kind: KindCat, Desc: "Country of the source IP (lowercase ISO alpha-2)", Model: true})
	reg(Def{Group: GroupNet, Name: "tz_ip_country_match", Kind: KindBucket, Max: 2, Buckets: []string{"mismatch", "match", "unknown"}, Desc: "Timezone country vs IP country", Model: true})
	reg(Def{Group: GroupNet, Name: "origin_mismatch", Kind: KindBool, Desc: "Origin at submit differs from origin at issue", Model: true})
	reg(Def{Group: GroupNet, Name: "ua_changed", Kind: KindBool, Desc: "UA header at submit differs from issue", Model: true})
	reg(Def{Group: GroupNet, Name: "ip24_changed", Kind: KindBool, Desc: "IP /24 (/48) at submit differs from issue", Model: true})
	reg(Def{Group: GroupNet, Name: "canvas_seed_conflict", Kind: KindBool, Desc: "Same canvas hash seen with a different seed within 24 h (replay)", Model: true})

	// ---- vel: velocity (section 3.5) ----
	for _, w := range []string{"1m", "10m", "1h"} {
		reg(Def{Group: GroupVelocity, Name: "ip_submits_" + w, Kind: KindCount, Max: 1e6, Desc: "Submits from this IP in the last " + w, Model: true})
		reg(Def{Group: GroupVelocity, Name: "ip24_submits_" + w, Kind: KindCount, Max: 1e6, Desc: "Submits from this /24 (/48) in the last " + w, Model: true})
		reg(Def{Group: GroupVelocity, Name: "ip24_distinct_fp_" + w, Kind: KindCount, Max: 1e6, Desc: "Distinct fingerprints from this /24 in the last " + w, Model: true})
		reg(Def{Group: GroupVelocity, Name: "fp_submits_" + w, Kind: KindCount, Max: 1e6, Desc: "Submits with this fingerprint in the last " + w, Model: true})
		reg(Def{Group: GroupVelocity, Name: "fp_distinct_ip24_" + w, Kind: KindCount, Max: 1e6, Desc: "Distinct /24s for this fingerprint in the last " + w, Model: true})
		reg(Def{Group: GroupVelocity, Name: "fp_distinct_asn_" + w, Kind: KindCount, Max: 1e6, Desc: "Distinct ASNs for this fingerprint in the last " + w, Model: true})
		reg(Def{Group: GroupVelocity, Name: "canvas_distinct_ua_" + w, Kind: KindCount, Max: 1e6, Desc: "Distinct UA families sharing this canvas hash in the last " + w, Model: true})
		reg(Def{Group: GroupVelocity, Name: "site_submits_" + w, Kind: KindCount, Max: 1e9, Desc: "Submits for this site in the last " + w, Model: true})
	}
	reg(Def{Group: GroupVelocity, Name: "ip_challenge_fail_1h", Kind: KindCount, Max: 1e6, Desc: "Failed challenges from this IP in the last hour", Model: true})
	reg(Def{Group: GroupVelocity, Name: "site_rate_ratio", Kind: KindFloat, Max: 1000, Desc: "Site submits in the last 10 min relative to the 7-day baseline for this hour", Model: true})
	reg(Def{Group: GroupVelocity, Name: "fp_interval_cv", Kind: KindFloat, Max: 10, Desc: "CV of inter-submit intervals for this fingerprint (>=10 events)", Model: true})
}
