// Package store defines persistence for sites, events, lists and replay
// tracking. Implementations live in store/sqlite (default) and
// store/postgres (cluster). Raw signals are never stored (design section 6).
package store

import (
	"context"
	"errors"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/nonce"
	"github.com/iamsuriyan/doorkeep/internal/scoring"
)

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = errors.New("store: not found")

// Site is a registered property.
type Site struct {
	ID                 string               `json:"id"`
	Name               string               `json:"name"`
	SiteKey            string               `json:"site_key"` // public dk_pk_...
	SecretHash         string               `json:"-"`        // SHA-256 hex of dk_sk_...
	Origins            []string             `json:"origins"`  // allowed origins (scheme://host[:port])
	Thresholds         scoring.Thresholds   `json:"thresholds"`
	Mode               scoring.SiteMode     `json:"mode"`
	InteractiveActions []string             `json:"interactive_actions"`
	StrictIP           bool                 `json:"strict_ip"`
	AccessibilityURL   string               `json:"accessibility_url,omitempty"` // escape hatch shown in challenges
	Actions            map[string]ActionCfg `json:"actions,omitempty"`
	CreatedAt          time.Time            `json:"created_at"`
}

// ActionCfg overrides thresholds per action.
type ActionCfg struct {
	Thresholds *scoring.Thresholds `json:"thresholds,omitempty"`
}

// ThresholdsFor returns the thresholds for an action.
func (s *Site) ThresholdsFor(action string) scoring.Thresholds {
	if a, ok := s.Actions[action]; ok && a.Thresholds != nil {
		return *a.Thresholds
	}
	if s.Thresholds.Challenge == 0 && s.Thresholds.Block == 0 {
		return scoring.DefaultThresholds
	}
	return s.Thresholds
}

// Event is one scored submission. Only bucketed and pseudonymous data.
type Event struct {
	ID            string           `json:"id"`
	SiteID        string           `json:"site_id"`
	TS            time.Time        `json:"ts"`
	Action        string           `json:"action"`
	Risk          int              `json:"risk"`
	Outcome       scoring.Outcome  `json:"outcome"`
	WouldBe       scoring.Outcome  `json:"would_be"`
	Reasons       []scoring.Reason `json:"reasons"`
	Shadow        []scoring.Reason `json:"shadow"`
	ShadowRisk    int              `json:"shadow_risk"`
	Features      scoring.Features `json:"-"`
	FPHash        string           `json:"fp_hash"`
	IP24Hash      string           `json:"-"`
	ASN           int              `json:"asn"`
	ASNClass      string           `json:"asn_class"`
	Country       string           `json:"country"`
	UAFamily      string           `json:"ua_family"`
	UAMajor       int              `json:"ua_major"`
	OSFamily      string           `json:"os_family"`
	ChallengeKind string           `json:"challenge_kind"`
	ChallengeOK   *bool            `json:"challenge_ok,omitempty"`
	VerifiedAt    *time.Time       `json:"verified_at,omitempty"`
	Label         string           `json:"label,omitempty"` // bot | human
	LabelSource   string           `json:"label_source,omitempty"`
}

// ListEntry is an allow/deny/always_challenge entry for a site.
type ListEntry struct {
	ID        int64              `json:"id"`
	SiteID    string             `json:"site_id"`
	Kind      string             `json:"kind"` // ip | cidr | asn | country | fp | ua_regex | crawler
	Value     string             `json:"value"`
	Action    scoring.ListAction `json:"action"`
	Note      string             `json:"note"`
	ExpiresAt *time.Time         `json:"expires_at,omitempty"`
}

// EventFilter narrows ListEvents.
type EventFilter struct {
	SiteID  string
	Since   time.Time
	Until   time.Time
	Outcome scoring.Outcome
	Reason  string
	FPHash  string
	IP24    string // day-scoped /24 hash ("today's events from IP x")
	Label   string
	Limit   int
}

// AdminSession is a dashboard login session.
type AdminSession struct {
	TokenHash string
	User      string
	CSRF      string
	ExpiresAt time.Time
}

// AuditEntry records one configuration change.
type AuditEntry struct {
	ID     int64          `json:"id"`
	TS     time.Time      `json:"ts"`
	Actor  string         `json:"actor"`
	Action string         `json:"action"`
	Target string         `json:"target"`
	Detail map[string]any `json:"detail"`
}

// SiteRule is a per-site override of a built-in rule (mode/weight) or a
// custom rule (full spec), stored as JSON.
type SiteRule struct {
	SiteID    string    `json:"site_id"`
	RuleID    string    `json:"rule_id"`
	Spec      []byte    `json:"spec"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Aggregate is one site-hour of counts, kept beyond event retention.
type Aggregate struct {
	Hour time.Time      `json:"hour"`
	Data map[string]any `json:"data"`
}

// Store is everything the server needs.
type Store interface {
	nonce.Store

	CreateSite(ctx context.Context, s *Site) error
	UpdateSite(ctx context.Context, s *Site) error
	SiteByKey(ctx context.Context, siteKey string) (*Site, error)
	SiteBySecretHash(ctx context.Context, secretHash string) (*Site, error)
	SiteByID(ctx context.Context, id string) (*Site, error)
	ListSites(ctx context.Context) ([]*Site, error)

	InsertEvent(ctx context.Context, e *Event) error
	UpdateEventChallenge(ctx context.Context, id, kind string, ok bool, risk int, outcome scoring.Outcome, reasons []scoring.Reason) error
	MarkEventVerified(ctx context.Context, id string, at time.Time) error
	LabelEvent(ctx context.Context, id, label, source string) error
	GetEvent(ctx context.Context, id string) (*Event, error)
	ListEvents(ctx context.Context, f EventFilter) ([]*Event, error)
	// StreamEvents calls fn for every event matching f (Limit ignored), in
	// time order. Used for stats, rollups and the rule lab.
	StreamEvents(ctx context.Context, f EventFilter, fn func(*Event) error) error
	DeleteEvent(ctx context.Context, id string) error
	PurgeEvents(ctx context.Context, before time.Time) (int64, error)

	// CanvasSeen records (site, canvasHash) -> seedHash and reports whether
	// the same canvas hash was seen with a different seed within window.
	CanvasSeen(ctx context.Context, siteID, canvasHash, seedHash string, now time.Time, window time.Duration) (conflict bool, err error)

	CreateAdmin(ctx context.Context, name, passwordHash string, now time.Time) error
	AdminPasswordHash(ctx context.Context, name string) (string, error)
	ListAdmins(ctx context.Context) ([]string, error)
	CreateSession(ctx context.Context, s *AdminSession, now time.Time) error
	GetSession(ctx context.Context, tokenHash string, now time.Time) (*AdminSession, error)
	DeleteSession(ctx context.Context, tokenHash string) error
	CreateAdminToken(ctx context.Context, tokenHash, name string, now time.Time) error
	AdminTokenName(ctx context.Context, tokenHash string) (string, error)
	Audit(ctx context.Context, e AuditEntry) error
	ListAudit(ctx context.Context, limit int) ([]AuditEntry, error)
	SiteRules(ctx context.Context, siteID string) ([]SiteRule, error)
	PutSiteRule(ctx context.Context, r SiteRule) error
	DeleteSiteRule(ctx context.Context, siteID, ruleID string) error
	PutAggregate(ctx context.Context, siteID string, a Aggregate) error
	Aggregates(ctx context.Context, siteID string, since, until time.Time) ([]Aggregate, error)

	SaveModels(ctx context.Context, snap map[string][]byte, now time.Time) error
	LoadModels(ctx context.Context) (map[string][]byte, error)

	ListEntries(ctx context.Context, siteID string, now time.Time) ([]ListEntry, error)
	AddListEntry(ctx context.Context, e *ListEntry) error
	DeleteListEntry(ctx context.Context, siteID string, id int64) error

	Close() error
}
