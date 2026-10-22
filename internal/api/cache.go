package api

import (
	"context"
	"sync"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/store"
)

// hotCacheTTL bounds how long another cluster node's site or list edit can
// take to reach this node. Writes through this node invalidate immediately.
const hotCacheTTL = 5 * time.Second

// cachedStore keeps the sites table and per-site list entries in memory for
// the hot paths (every submit and every edge sub-request read them), so a
// protected page hit does not scan the database.
type cachedStore struct {
	store.Store

	mu      sync.Mutex
	sites   []*store.Site
	sitesAt time.Time
	lists   map[string]cachedList
}

type cachedList struct {
	entries []store.ListEntry
	at      time.Time
}

func newCachedStore(st store.Store) *cachedStore {
	if c, ok := st.(*cachedStore); ok {
		return c
	}
	return &cachedStore{Store: st, lists: map[string]cachedList{}}
}

func (c *cachedStore) invalidateSites() {
	c.mu.Lock()
	c.sites = nil
	c.mu.Unlock()
}

func (c *cachedStore) invalidateLists(siteID string) {
	c.mu.Lock()
	delete(c.lists, siteID)
	c.mu.Unlock()
}

func (c *cachedStore) ListSites(ctx context.Context) ([]*store.Site, error) {
	c.mu.Lock()
	if c.sites != nil && time.Since(c.sitesAt) < hotCacheTTL {
		s := c.sites
		c.mu.Unlock()
		return s, nil
	}
	c.mu.Unlock()
	sites, err := c.Store.ListSites(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.sites, c.sitesAt = sites, time.Now()
	c.mu.Unlock()
	return sites, nil
}

// cachedSite looks a site up in the cached table; ok is false on a miss so
// the caller falls through to the database (a site just created elsewhere).
func (c *cachedStore) cachedSite(ctx context.Context, match func(*store.Site) bool) (*store.Site, bool) {
	sites, err := c.ListSites(ctx)
	if err != nil {
		return nil, false
	}
	for _, s := range sites {
		if match(s) {
			cp := *s
			return &cp, true
		}
	}
	return nil, false
}

func (c *cachedStore) SiteByKey(ctx context.Context, key string) (*store.Site, error) {
	if s, ok := c.cachedSite(ctx, func(s *store.Site) bool { return s.SiteKey == key }); ok {
		return s, nil
	}
	return c.Store.SiteByKey(ctx, key)
}

func (c *cachedStore) SiteByID(ctx context.Context, id string) (*store.Site, error) {
	if s, ok := c.cachedSite(ctx, func(s *store.Site) bool { return s.ID == id }); ok {
		return s, nil
	}
	return c.Store.SiteByID(ctx, id)
}

func (c *cachedStore) CreateSite(ctx context.Context, s *store.Site) error {
	defer c.invalidateSites()
	return c.Store.CreateSite(ctx, s)
}

func (c *cachedStore) UpdateSite(ctx context.Context, s *store.Site) error {
	defer c.invalidateSites()
	return c.Store.UpdateSite(ctx, s)
}

// ListEntries caches the site's entries and drops expired ones at read time.
func (c *cachedStore) ListEntries(ctx context.Context, siteID string, now time.Time) ([]store.ListEntry, error) {
	c.mu.Lock()
	cl, ok := c.lists[siteID]
	c.mu.Unlock()
	if !ok || time.Since(cl.at) >= hotCacheTTL {
		// Fetch everything not yet expired at the zero time; expiry is
		// applied below against the caller's clock.
		entries, err := c.Store.ListEntries(ctx, siteID, time.Time{})
		if err != nil {
			return nil, err
		}
		cl = cachedList{entries: entries, at: time.Now()}
		c.mu.Lock()
		c.lists[siteID] = cl
		c.mu.Unlock()
	}
	out := make([]store.ListEntry, 0, len(cl.entries))
	for _, e := range cl.entries {
		if e.ExpiresAt == nil || e.ExpiresAt.After(now) {
			out = append(out, e)
		}
	}
	return out, nil
}

func (c *cachedStore) AddListEntry(ctx context.Context, e *store.ListEntry) error {
	defer c.invalidateLists(e.SiteID)
	return c.Store.AddListEntry(ctx, e)
}

func (c *cachedStore) DeleteListEntry(ctx context.Context, siteID string, id int64) error {
	defer c.invalidateLists(siteID)
	return c.Store.DeleteListEntry(ctx, siteID, id)
}
