// Command load measures doorkeep under sustained traffic: each iteration is
// the full session -> submit -> siteverify cycle, from varied client
// addresses (X-Forwarded-For; run doorkeep with DOORKEEP_TRUSTED_PROXIES=127.0.0.1).
//
//	go run ./testing/load -url http://127.0.0.1:18181 -key dk_pk_.. -secret dk_sk_.. -origin http://localhost:9 -rps 200 -d 30s
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/signals/payload"
)

const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

type rec struct {
	mu   sync.Mutex
	lat  map[string][]time.Duration
	errs map[string]int
}

func (r *rec) add(ep string, d time.Duration, err bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err {
		r.errs[ep]++
		return
	}
	r.lat[ep] = append(r.lat[ep], d)
}

var client = &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 512, MaxConnsPerHost: 512}, Timeout: 10 * time.Second}

func call(base, path, body, ip, origin string, form bool) (map[string]any, time.Duration, error) {
	req, _ := http.NewRequest("POST", base+path, strings.NewReader(body))
	if form {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set("Origin", origin)
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept-Language", "en")
		req.Header.Set("X-Forwarded-For", ip)
	}
	t0 := time.Now()
	res, err := client.Do(req)
	d := time.Since(t0)
	if err != nil {
		return nil, d, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if res.StatusCode >= 400 {
		return out, d, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	return out, d, nil
}

func payloadFor(n string) string {
	p := payload.Payload{V: 1, N: n, A: "signup",
		T:    payload.Timing{I: 100, F: 400, S: 1100, D: float64(time.Now().UnixMilli())},
		Auto: payload.Auto{Geo: []float64{1280, 657, 1280, 760, 0}, Plg: []int{5, 0}, Chr: 1, Voices: 12, Conn: 1},
		FP: payload.FP{UA: ua, Scr: []float64{1920, 1080, 1920, 1040, 24, 1, 0}, TZ: "Asia/Kolkata", TZO: -330, Lang: []string{"en-IN", "en"},
			GL: []string{"Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11)"}, CV: payload.Canvas{H: n[:11], S: n[11:22]}, HC: 8, Tch: 16, Feat: "_w8"},
		Beh: payload.Beh{Ptr: []float64{120, 4000, 0.4, 0.9, 30, 50, 0.6, 0.01, 0, 3, 30, 60, 20, 5, 2}, Key: []float64{20, 90, 0.3, 0.5, 0.05, 0, 0}, Foc: []float64{1, 1, 0, 0}},
		Env:  payload.Env{Sto: 15, Perf: []float64{0, 300, 20, 0}, SV: 1}}
	b, _ := json.Marshal(p)
	return string(b)
}

func pct(ds []time.Duration, p float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	return ds[int(float64(len(ds)-1)*p)]
}

func main() {
	base := flag.String("url", "http://127.0.0.1:18181", "doorkeep URL")
	key := flag.String("key", "", "site key")
	secret := flag.String("secret", "", "site secret")
	origin := flag.String("origin", "", "site origin")
	rps := flag.Int("rps", 200, "full cycles started per second")
	dur := flag.Duration("d", 30*time.Second, "duration")
	flag.Parse()
	r := &rec{lat: map[string][]time.Duration{}, errs: map[string]int{}}
	var wg sync.WaitGroup
	tick := time.NewTicker(time.Second / time.Duration(*rps))
	defer tick.Stop()
	end := time.Now().Add(*dur)
	started := 0
	for time.Now().Before(end) {
		<-tick.C
		started++
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := fmt.Sprintf("10.%d.%d.%d", rand.IntN(250), rand.IntN(250), 1+rand.IntN(250))
			s, d, err := call(*base, "/v1/session", `{"sk":"`+*key+`","a":"signup"}`, ip, *origin, false)
			r.add("session", d, err != nil)
			if err != nil {
				return
			}
			n := s["nonce"].(string)
			time.Sleep(1100 * time.Millisecond) // the person fills the form
			sub, d, err := call(*base, "/v1/submit", payloadFor(n), ip, *origin, false)
			r.add("submit", d, err != nil)
			tok, _ := sub["token"].(string)
			if err != nil || tok == "" {
				if err == nil {
					r.add("submit-not-ok", 0, true)
				}
				return
			}
			_, d, err = call(*base, "/v1/siteverify", url.Values{"secret": {*secret}, "response": {tok}}.Encode(), "", "", true)
			r.add("verify", d, err != nil)
		}()
	}
	wg.Wait()
	fmt.Printf("target %d cycles/s for %s (%d cycles, %.0f HTTP requests/s)\n", *rps, *dur, started, float64(started*3)/dur.Seconds())
	fmt.Printf("%-8s %8s %10s %10s %10s %6s\n", "endpoint", "count", "p50", "p95", "p99", "errors")
	for _, ep := range []string{"session", "submit", "verify"} {
		ds := r.lat[ep]
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		fmt.Printf("%-8s %8d %10s %10s %10s %6d\n", ep, len(ds), pct(ds, .5).Round(10*time.Microsecond), pct(ds, .95).Round(10*time.Microsecond), pct(ds, .99).Round(10*time.Microsecond), r.errs[ep])
	}
	if r.errs["submit-not-ok"] > 0 {
		fmt.Println("submits not minted (challenged):", r.errs["submit-not-ok"])
	}
	if r.errs["session"]+r.errs["submit"]+r.errs["verify"] > 0 {
		os.Exit(1)
	}
}
