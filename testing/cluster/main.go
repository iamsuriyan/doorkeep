// Command cluster drives a two-node doorkeep cluster (shared Postgres and
// Redis) through one session that hops between nodes, and checks that
// single use and velocity are cluster-wide.
//
//	go run ./testing/cluster -a http://127.0.0.1:18201 -b http://127.0.0.1:18202 -key dk_pk_.. -secret dk_sk_.. -origin http://localhost:9
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/challenge/pow"
	"github.com/iamsuriyan/doorkeep/internal/signals/payload"
)

const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

var origin string

func post(base, path, body string, form bool) map[string]any {
	req, _ := http.NewRequest("POST", base+path, strings.NewReader(body))
	if form {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req.Header.Set("Content-Type", "text/plain")
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept-Language", "en")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("request failed:", err)
		os.Exit(1)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	var out map[string]any
	json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]any{}
	}
	out["_status"] = res.StatusCode
	return out
}

func human(n string, elapsed time.Duration, canvas string) string {
	p := payload.Payload{V: 1, N: n, A: "signup",
		T:    payload.Timing{I: 100, F: 120, S: 100 + float64(elapsed.Milliseconds())*0.9, D: float64(time.Now().UnixMilli())},
		Auto: payload.Auto{Geo: []float64{1280, 657, 1280, 760, 0}, Plg: []int{5, 0}, Chr: 1, Voices: 12, Conn: 1},
		FP: payload.FP{UA: ua, Scr: []float64{1920, 1080, 1920, 1040, 24, 1, 0}, TZ: "Asia/Kolkata", TZO: -330, Lang: []string{"en-IN", "en"},
			GL: []string{"Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11)"}, CV: payload.Canvas{H: canvas, S: "St4tIcCanvs"}, HC: 8, Tch: 16, Feat: "_w8"},
		Beh: payload.Beh{Ptr: []float64{120, 4000, 0.4, 0.9, 30, 50, 0.6, 0.01, 0, 3, 30, 60, 20, 5, 2}, Key: []float64{20, 90, 0.3, 0.5, 0.05, 0, 0}, Foc: []float64{1, 1, 0, 0}},
		Env: payload.Env{Sto: 15, Perf: []float64{0, 300, 20, 0}, SV: 1}}
	b, _ := json.Marshal(p)
	return string(b)
}

func check(ok bool, msg string) {
	if ok {
		fmt.Println("PASS", msg)
		return
	}
	fmt.Println("FAIL", msg)
	os.Exit(1)
}

func main() {
	a := flag.String("a", "", "node A")
	b := flag.String("b", "", "node B")
	key := flag.String("key", "", "site key")
	secret := flag.String("secret", "", "site secret")
	flag.StringVar(&origin, "origin", "", "site origin")
	flag.Parse()

	s := post(*a, "/v1/session", `{"sk":"`+*key+`","a":"signup"}`, false)
	n, _ := s["nonce"].(string)
	check(n != "", "session issued on node A")
	time.Sleep(1200 * time.Millisecond)
	sub := post(*b, "/v1/submit", human(n, 1200*time.Millisecond, n[:11]), false)
	tok, _ := sub["token"].(string)
	check(tok != "", fmt.Sprintf("same nonce submitted on node B (status %v)", sub["status"]))
	again := post(*a, "/v1/submit", human(n, 1200*time.Millisecond, n[:11]), false)
	check(again["_status"] == 409, "second submit of that nonce on node A refused (cluster-wide single use)")
	v := post(*a, "/v1/siteverify", url.Values{"secret": {*secret}, "response": {tok}}.Encode(), true)
	check(v["success"] == true, "token minted on B verifies on A")
	v2 := post(*b, "/v1/siteverify", url.Values{"secret": {*secret}, "response": {tok}}.Encode(), true)
	codes, _ := json.Marshal(v2["error-codes"])
	check(v2["success"] == false && strings.Contains(string(codes), "timeout-or-duplicate"), "replaying it on B returns timeout-or-duplicate")

	// Velocity is shared: 22 submits alternating between nodes trip IP_BURST.
	var last map[string]any
	for i := 0; i < 22; i++ {
		node := *a
		if i%2 == 1 {
			node = *b
		}
		s := post(node, "/v1/session", `{"sk":"`+*key+`","a":"signup"}`, false)
		n, _ := s["nonce"].(string)
		check(n != "", fmt.Sprintf("session %d on node %d", i, i%2))
		time.Sleep(60 * time.Millisecond)
		last = post(node, "/v1/submit", human(n, 60*time.Millisecond, n[:11]), false)
		if last["status"] == "challenge" {
			pm := last["pow"].(map[string]any)
			params := pow.Params{Salt: pm["salt"].(string), Bits: int(pm["bits"].(float64)), N: int(pm["n"].(float64))}
			b, _ := json.Marshal(map[string]any{"n": n, "kind": "pow", "sol": pow.Solve(n, params)})
			last = post(node, "/v1/challenge", string(b), false)
		}
		check(last["status"] == "ok" || last["status"] == "challenge", fmt.Sprintf("submit %d accepted for scoring (status %v %v)", i, last["status"], last["error"]))
	}
	tok2, _ := last["token"].(string)
	reasons := ""
	if tok2 != "" {
		vv := post(*a, "/v1/siteverify", url.Values{"secret": {*secret}, "response": {tok2}}.Encode(), true)
		if dk, ok := vv["doorkeep"].(map[string]any); ok {
			r, _ := json.Marshal(dk["reasons"])
			reasons = string(r)
		}
	}
	check(strings.Contains(reasons, "IP_BURST"), "burst split across both nodes detected: "+reasons)
}
