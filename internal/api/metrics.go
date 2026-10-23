package api

import (
	"fmt"
	"io"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/signals/velocity"
)

// Prometheus metrics in the text exposition format, without a client
// library. Label values are bounded: routes are ServeMux patterns, sites
// are registered site IDs, outcomes and challenge kinds are fixed sets.

// Version is reported as doorkeep_build_info; main sets it.
var Version = "dev"

var latencyBuckets = []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5}

type histogram struct {
	counts []uint64 // per bucket, cumulative on output
	sum    float64
	n      uint64
}

type metrics struct {
	mu       sync.Mutex
	requests map[[2]string]uint64  // route, status code
	latency  map[string]*histogram // route
	counters map[string]uint64     // full sample name with labels -> value
	started  time.Time
}

func newMetrics() *metrics {
	return &metrics{requests: map[[2]string]uint64{}, latency: map[string]*histogram{}, counters: map[string]uint64{}, started: time.Now()}
}

// observe records one request. route is the matched ServeMux pattern.
func (m *metrics) observe(route string, code int, d time.Duration) {
	if route == "" {
		route = "unmatched"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[[2]string{route, strconv.Itoa(code)}]++
	h := m.latency[route]
	if h == nil {
		h = &histogram{counts: make([]uint64, len(latencyBuckets))}
		m.latency[route] = h
	}
	s := d.Seconds()
	for i, b := range latencyBuckets {
		if s <= b {
			h.counts[i]++
			break
		}
	}
	h.sum += s
	h.n++
}

// inc adds one to a counter. name is "metric" plus optional label pairs.
func (m *metrics) inc(name string, labels ...string) {
	if m == nil {
		return
	}
	key := name + fmtLabels(labels...)
	m.mu.Lock()
	m.counters[key]++
	m.mu.Unlock()
}

func fmtLabels(kv ...string) string {
	if len(kv) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i+1 < len(kv); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(kv[i])
		b.WriteString(`="`)
		b.WriteString(strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(kv[i+1]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

var counterHelp = map[string]string{
	"doorkeep_submits_total":         "Scored submissions by site and outcome before any challenge.",
	"doorkeep_tokens_total":          "Tokens minted by site, final outcome and challenge passed.",
	"doorkeep_challenges_total":      "Challenge answers by kind (pow, visual) and result (ok, fail, exhausted).",
	"doorkeep_verifications_total":   "siteverify calls by result (success, failure, invalid).",
	"doorkeep_edge_decisions_total":  "Edge-mode auth sub-requests by result (pass, check, deny).",
	"doorkeep_rate_limited_total":    "Session requests refused by the per-address rate limit.",
	"doorkeep_internal_errors_total": "Requests that failed on a store or internal error.",
}

func (s *Server) writeMetrics(w io.Writer) {
	m := s.metrics
	m.mu.Lock()
	reqs := make(map[[2]string]uint64, len(m.requests))
	for k, v := range m.requests {
		reqs[k] = v
	}
	lat := make(map[string]histogram, len(m.latency))
	for k, h := range m.latency {
		lat[k] = histogram{counts: slices.Clone(h.counts), sum: h.sum, n: h.n}
	}
	ctr := make(map[string]uint64, len(m.counters))
	for k, v := range m.counters {
		ctr[k] = v
	}
	m.mu.Unlock()

	fmt.Fprintf(w, "# HELP doorkeep_build_info Build version.\n# TYPE doorkeep_build_info gauge\ndoorkeep_build_info%s 1\n",
		fmtLabels("version", Version, "goversion", runtime.Version()))
	fmt.Fprintf(w, "# HELP doorkeep_start_time_seconds Process start time.\n# TYPE doorkeep_start_time_seconds gauge\ndoorkeep_start_time_seconds %d\n", m.started.Unix())

	fmt.Fprint(w, "# HELP doorkeep_http_requests_total HTTP requests by route and status.\n# TYPE doorkeep_http_requests_total counter\n")
	keys := make([][2]string, 0, len(reqs))
	for k := range reqs {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b [2]string) int { return strings.Compare(a[0]+a[1], b[0]+b[1]) })
	for _, k := range keys {
		fmt.Fprintf(w, "doorkeep_http_requests_total%s %d\n", fmtLabels("route", k[0], "code", k[1]), reqs[k])
	}

	fmt.Fprint(w, "# HELP doorkeep_http_request_duration_seconds Request latency by route.\n# TYPE doorkeep_http_request_duration_seconds histogram\n")
	routes := make([]string, 0, len(lat))
	for r := range lat {
		routes = append(routes, r)
	}
	slices.Sort(routes)
	for _, r := range routes {
		h := lat[r]
		var cum uint64
		for i, b := range latencyBuckets {
			cum += h.counts[i]
			fmt.Fprintf(w, "doorkeep_http_request_duration_seconds_bucket%s %d\n", fmtLabels("route", r, "le", strconv.FormatFloat(b, 'g', -1, 64)), cum)
		}
		fmt.Fprintf(w, "doorkeep_http_request_duration_seconds_bucket%s %d\n", fmtLabels("route", r, "le", "+Inf"), h.n)
		fmt.Fprintf(w, "doorkeep_http_request_duration_seconds_sum%s %g\n", fmtLabels("route", r), h.sum)
		fmt.Fprintf(w, "doorkeep_http_request_duration_seconds_count%s %d\n", fmtLabels("route", r), h.n)
	}

	names := make([]string, 0, len(counterHelp))
	for n := range counterHelp {
		names = append(names, n)
	}
	slices.Sort(names)
	samples := make([]string, 0, len(ctr))
	for k := range ctr {
		samples = append(samples, k)
	}
	slices.Sort(samples)
	for _, n := range names {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", n, counterHelp[n], n)
		for _, k := range samples {
			if k == n || strings.HasPrefix(k, n+"{") {
				fmt.Fprintf(w, "%s %d\n", k, ctr[k])
			}
		}
	}

	db := s.IP.Get()
	fmt.Fprint(w, "# HELP doorkeep_ipdata_entries Loaded IP intelligence entries by kind.\n# TYPE doorkeep_ipdata_entries gauge\n")
	counts := db.Counts()
	kinds := make([]string, 0, len(counts))
	for k := range counts {
		kinds = append(kinds, k)
	}
	slices.Sort(kinds)
	for _, k := range kinds {
		fmt.Fprintf(w, "doorkeep_ipdata_entries%s %d\n", fmtLabels("kind", k), counts[k])
	}
	if !db.Updated.IsZero() {
		fmt.Fprintf(w, "# HELP doorkeep_ipdata_updated_time_seconds When the IP intelligence files were last downloaded.\n# TYPE doorkeep_ipdata_updated_time_seconds gauge\ndoorkeep_ipdata_updated_time_seconds %d\n", db.Updated.Unix())
	}

	switch v := s.Vel.(type) {
	case *velocity.Tracker:
		fmt.Fprintf(w, "# HELP doorkeep_velocity_keys Keys held by the in-memory velocity tracker.\n# TYPE doorkeep_velocity_keys gauge\ndoorkeep_velocity_keys %d\n", v.Len())
	case *velocity.Redis:
		fmt.Fprintf(w, "# HELP doorkeep_velocity_keys Keys held by the in-memory velocity tracker.\n# TYPE doorkeep_velocity_keys gauge\ndoorkeep_velocity_keys %d\n", v.Local().Len())
		fmt.Fprintf(w, "# HELP doorkeep_redis_errors_total Redis velocity calls that failed and fell back to this node's counts.\n# TYPE doorkeep_redis_errors_total counter\ndoorkeep_redis_errors_total %d\n", v.Errors())
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fmt.Fprintf(w, "# HELP go_goroutines Goroutines.\n# TYPE go_goroutines gauge\ngo_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(w, "# HELP go_memstats_heap_inuse_bytes Heap in use.\n# TYPE go_memstats_heap_inuse_bytes gauge\ngo_memstats_heap_inuse_bytes %d\n", ms.HeapInuse)
	fmt.Fprintf(w, "# HELP go_memstats_sys_bytes Memory obtained from the OS.\n# TYPE go_memstats_sys_bytes gauge\ngo_memstats_sys_bytes %d\n", ms.Sys)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.writeMetrics(w)
}

// statusWriter records the response status for request metrics.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (sw *statusWriter) WriteHeader(code int) {
	if sw.code == 0 {
		sw.code = code
	}
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	if sw.code == 0 {
		sw.code = http.StatusOK
	}
	return sw.ResponseWriter.Write(b)
}

func (sw *statusWriter) Unwrap() http.ResponseWriter { return sw.ResponseWriter }
