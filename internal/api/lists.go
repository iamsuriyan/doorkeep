package api

import (
	"context"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/scoring"
)

// matchLists evaluates the site's allow/deny/always_challenge entries.
// Precedence: allow > deny > always_challenge, so an operator's allow-list
// always wins (design section 4.3).
func (s *Server) matchLists(ctx context.Context, siteID string, ip netip.Addr, fpHash, ua string, now time.Time) (scoring.ListAction, string) {
	entries, err := s.Store.ListEntries(ctx, siteID, now)
	if err != nil || len(entries) == 0 {
		return "", ""
	}
	var best scoring.ListAction
	var code string
	rank := map[scoring.ListAction]int{scoring.ListAllow: 3, scoring.ListDeny: 2, scoring.ListAlwaysChallenge: 1}
	for _, e := range entries {
		if !listMatch(e.Kind, e.Value, ip, fpHash, ua) {
			continue
		}
		if rank[e.Action] > rank[best] {
			best = e.Action
			prefix := map[scoring.ListAction]string{scoring.ListAllow: "ALLOWLIST_", scoring.ListDeny: "DENYLIST_", scoring.ListAlwaysChallenge: "ALWAYS_CHALLENGE_"}[e.Action]
			code = prefix + strings.ToUpper(e.Kind)
		}
	}
	return best, code
}

func listMatch(kind, value string, ip netip.Addr, fpHash, ua string) bool {
	switch kind {
	case "ip":
		a, err := netip.ParseAddr(value)
		return err == nil && a.Unmap() == ip
	case "cidr":
		p, err := netip.ParsePrefix(value)
		return err == nil && p.Contains(ip)
	case "fp":
		return value != "" && strings.HasPrefix(fpHash, strings.ToLower(value))
	case "ua_regex":
		re, err := regexp.Compile(value)
		return err == nil && re.MatchString(ua)
	}
	// asn, country and crawler kinds are matched once ipintel lands (M2).
	return false
}
