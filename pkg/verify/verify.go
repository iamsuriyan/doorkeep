// Package verify is the Go client a site backend uses to check a doorkeep
// token (the dk-response form field) with /v1/siteverify.
//
//	v := verify.New("https://dk.example.com", os.Getenv("DOORKEEP_SECRET"))
//	res, err := v.Verify(ctx, r.FormValue("dk-response"), verify.Options{Action: "signup", RemoteIP: ip})
//	if err != nil || !res.Success { reject }
package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FailMode decides what Verify reports when doorkeep cannot be reached.
type FailMode int

const (
	// FailClosed treats an unreachable doorkeep as a failed check (default).
	FailClosed FailMode = iota
	// FailOpen lets requests through when doorkeep is unreachable. Use only
	// for low-risk forms.
	FailOpen
)

// Client verifies tokens.
type Client struct {
	Endpoint string
	Secret   string
	HTTP     *http.Client
	Fail     FailMode
}

// New returns a client with a 3-second timeout.
func New(endpoint, secret string) *Client {
	return &Client{Endpoint: strings.TrimRight(endpoint, "/"), Secret: secret, HTTP: &http.Client{Timeout: 3 * time.Second}}
}

// Options are optional checks performed by doorkeep.
type Options struct {
	Action   string // expected action, e.g. "signup"
	Hostname string // expected hostname
	RemoteIP string // client IP, checked when the site has strict_ip
}

// Result mirrors the siteverify response.
type Result struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	Action      string   `json:"action"`
	ErrorCodes  []string `json:"error-codes"`
	Score       float64  `json:"score"`
	Doorkeep    struct {
		EventID   string   `json:"event_id"`
		Risk      int      `json:"risk"`
		Outcome   string   `json:"outcome"`
		Reasons   []string `json:"reasons"`
		Challenge string   `json:"challenge"`
	} `json:"doorkeep"`
	// FailedOpen is true when doorkeep was unreachable and FailOpen applied.
	FailedOpen bool `json:"-"`
}

// ErrUnavailable is returned (with FailClosed) when doorkeep cannot be reached.
var ErrUnavailable = errors.New("doorkeep: verify unavailable")

// Verify checks a token. A missing token is a normal failed result.
func (c *Client) Verify(ctx context.Context, response string, o Options) (*Result, error) {
	if response == "" {
		return &Result{Success: false, ErrorCodes: []string{"missing-input-response"}}, nil
	}
	form := url.Values{"secret": {c.Secret}, "response": {response}}
	if o.Action != "" {
		form.Set("expected_action", o.Action)
	}
	if o.Hostname != "" {
		form.Set("expected_hostname", o.Hostname)
	}
	if o.RemoteIP != "" {
		form.Set("remoteip", o.RemoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+"/v1/siteverify", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 3 * time.Second}
	}
	res, err := hc.Do(req)
	if err != nil || res.StatusCode >= 500 {
		if res != nil {
			res.Body.Close()
		}
		if c.Fail == FailOpen {
			return &Result{Success: true, FailedOpen: true}, nil
		}
		if err == nil {
			err = fmt.Errorf("HTTP %d", res.StatusCode)
		}
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer res.Body.Close()
	var out Result
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&out); err != nil {
		return nil, fmt.Errorf("doorkeep: bad verify response: %w", err)
	}
	return &out, nil
}

// Report labels an event so the site's supervised model learns from your
// own ground truth (e.g. the signup later turned out to be spam).
func (c *Client) Report(ctx context.Context, eventID string, bot bool) error {
	label := "human"
	if bot {
		label = "bot"
	}
	form := url.Values{"secret": {c.Secret}, "event_id": {eventID}, "label": {label}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+"/v1/report", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 3 * time.Second}
	}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	var out struct {
		Success    bool     `json:"success"`
		ErrorCodes []string `json:"error-codes"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return err
	}
	if !out.Success {
		return fmt.Errorf("doorkeep: report failed: %v", out.ErrorCodes)
	}
	return nil
}
