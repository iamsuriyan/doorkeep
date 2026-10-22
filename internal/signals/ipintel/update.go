package ipintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Source is one downloadable dataset.
type Source struct {
	Name    string
	URL     string
	File    string
	License string
}

// Sources are the datasets `doorkeep ipdata update` fetches. Each is
// published by its owner for this kind of use; licences are recorded in
// sources.json next to the data and rendered on the dashboard.
var Sources = []Source{
	{"iptoasn combined", "https://iptoasn.com/data/ip2asn-combined.tsv.gz", FileASN, "PDDL 1.0 (public domain)"},
	{"Tor exit list", "https://check.torproject.org/torbulkexitlist", FileTor, "Published by the Tor Project for this purpose"},
	{"Spamhaus DROP v4", "https://www.spamhaus.org/drop/drop_v4.json", FileDropV4, "Spamhaus DROP terms: free use, fetched at runtime, not redistributed"},
	{"Spamhaus DROP v6", "https://www.spamhaus.org/drop/drop_v6.json", FileDropV6, "Spamhaus DROP terms: free use, fetched at runtime, not redistributed"},
}

// crawlerFeeds are published IP range files for verified crawlers, all in
// the {"prefixes":[{"ipv4Prefix"|"ipv6Prefix": "..."}]} format.
var crawlerFeeds = map[string]string{
	"googlebot": "https://developers.google.com/static/search/apis/ipranges/googlebot.json",
	"bingbot":   "https://www.bing.com/toolbox/bingbot.json",
	"gptbot":    "https://openai.com/gptbot.json",
}

// Update downloads every source into dir atomically. Failures of one
// source do not discard the others; the returned error lists failures.
func Update(ctx context.Context, dir string, client *http.Client) error {
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var failed []string
	manifest := map[string]any{"updated": time.Now().UTC().Format(time.RFC3339)}
	var got []map[string]string
	for _, s := range Sources {
		if err := fetchTo(ctx, client, s.URL, filepath.Join(dir, s.File)); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", s.Name, err))
			continue
		}
		got = append(got, map[string]string{"name": s.Name, "url": s.URL, "license": s.License})
	}
	crawlers := map[string][]string{}
	for name, url := range crawlerFeeds {
		var doc struct {
			Prefixes []struct {
				V4 string `json:"ipv4Prefix"`
				V6 string `json:"ipv6Prefix"`
			} `json:"prefixes"`
		}
		if err := fetchJSON(ctx, client, url, &doc); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		for _, p := range doc.Prefixes {
			if p.V4 != "" {
				crawlers[name] = append(crawlers[name], p.V4)
			}
			if p.V6 != "" {
				crawlers[name] = append(crawlers[name], p.V6)
			}
		}
		got = append(got, map[string]string{"name": name + " ranges", "url": url, "license": "Published by the operator for verification"})
	}
	if len(crawlers) > 0 {
		b, _ := json.Marshal(crawlers)
		if err := writeAtomic(filepath.Join(dir, FileCrawlers), b); err != nil {
			failed = append(failed, "crawlers: "+err.Error())
		}
	}
	manifest["sources"] = got
	manifest["failed"] = failed
	b, _ := json.MarshalIndent(manifest, "", "  ")
	_ = writeAtomic(filepath.Join(dir, "sources.json"), b)
	if len(failed) > 0 {
		return fmt.Errorf("ipintel: %d source(s) failed: %v", len(failed), failed)
	}
	return nil
}

func fetchTo(ctx context.Context, c *http.Client, url, path string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "doorkeep-ipdata/1 (+https://github.com/iamsuriyan/doorkeep)")
	res, err := c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", res.StatusCode)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, io.LimitReader(res.Body, 512<<20)); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func fetchJSON(ctx context.Context, c *http.Client, url string, v any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "doorkeep-ipdata/1 (+https://github.com/iamsuriyan/doorkeep)")
	res, err := c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 32<<20)).Decode(v)
}

func writeAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
