// Package sqlite is the default single-binary store, using the CGO-free
// modernc.org/sqlite driver in WAL mode. All writes go through one
// connection so nonce transitions are serialised; reads use a separate pool.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"

	"github.com/iamsuriyan/doorkeep/internal/nonce"
	"github.com/iamsuriyan/doorkeep/internal/scoring"
	"github.com/iamsuriyan/doorkeep/internal/store"
)

//go:embed migrations/*.sql
var migrations embed.FS

// DB implements store.Store.
type DB struct {
	w *sql.DB // single writer connection
	r *sql.DB // reader pool
}

var _ store.Store = (*DB)(nil)

// Open opens (creating if needed) the database at path and runs migrations.
// Use ":memory:" only in tests via OpenMemory.
func Open(path string) (*DB, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_txlock=immediate"
	w, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	r, err := sql.Open("sqlite", dsn+"&mode=ro")
	if err != nil {
		w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(8)
	db := &DB{w: w, r: r}
	if err := db.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// OpenMemory opens a shared in-memory database for tests.
func OpenMemory(name string) (*DB, error) {
	dsn := "file:" + name + "?mode=memory&cache=shared&_pragma=busy_timeout(5000)&_txlock=immediate"
	w, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	db := &DB{w: w, r: w}
	if err := db.migrate(); err != nil {
		return nil, err
	}
	return db, nil
}

func (db *DB) migrate() error {
	goose.SetBaseFS(migrations)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("sqlite3"); err != nil {
		return err
	}
	return goose.Up(db.w, "migrations")
}

// Close closes both pools.
func (db *DB) Close() error {
	err := db.w.Close()
	if db.r != db.w {
		if e := db.r.Close(); err == nil {
			err = e
		}
	}
	return err
}

func ms(t time.Time) int64 { return t.UnixMilli() }
func fromMS(v int64) time.Time {
	return time.UnixMilli(v).UTC()
}

// ---------------- sites ----------------

type siteConfig struct {
	Origins            []string                   `json:"origins"`
	Thresholds         scoring.Thresholds         `json:"thresholds"`
	Mode               scoring.SiteMode           `json:"mode"`
	InteractiveActions []string                   `json:"interactive_actions"`
	StrictIP           bool                       `json:"strict_ip"`
	Actions            map[string]store.ActionCfg `json:"actions,omitempty"`
	AccessibilityURL   string                     `json:"accessibility_url,omitempty"`
}

func (db *DB) CreateSite(ctx context.Context, s *store.Site) error {
	cfg, _ := json.Marshal(siteConfig{s.Origins, s.Thresholds, s.Mode, s.InteractiveActions, s.StrictIP, s.Actions, s.AccessibilityURL})
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	_, err := db.w.ExecContext(ctx, `INSERT INTO sites(id,name,site_key,secret_hash,config,created_at) VALUES(?,?,?,?,?,?)`,
		s.ID, s.Name, s.SiteKey, s.SecretHash, string(cfg), ms(s.CreatedAt))
	return err
}

func (db *DB) UpdateSite(ctx context.Context, s *store.Site) error {
	cfg, _ := json.Marshal(siteConfig{s.Origins, s.Thresholds, s.Mode, s.InteractiveActions, s.StrictIP, s.Actions, s.AccessibilityURL})
	res, err := db.w.ExecContext(ctx, `UPDATE sites SET name=?, secret_hash=?, config=? WHERE id=?`, s.Name, s.SecretHash, string(cfg), s.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (db *DB) siteWhere(ctx context.Context, where string, arg any) (*store.Site, error) {
	row := db.r.QueryRowContext(ctx, `SELECT id,name,site_key,secret_hash,config,created_at FROM sites WHERE `+where, arg)
	return scanSite(row)
}

type scanner interface{ Scan(...any) error }

func scanSite(row scanner) (*store.Site, error) {
	var s store.Site
	var cfgS string
	var created int64
	if err := row.Scan(&s.ID, &s.Name, &s.SiteKey, &s.SecretHash, &cfgS, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	var cfg siteConfig
	if err := json.Unmarshal([]byte(cfgS), &cfg); err != nil {
		return nil, err
	}
	s.Origins, s.Thresholds, s.Mode, s.InteractiveActions, s.StrictIP, s.Actions, s.AccessibilityURL = cfg.Origins, cfg.Thresholds, cfg.Mode, cfg.InteractiveActions, cfg.StrictIP, cfg.Actions, cfg.AccessibilityURL
	if s.Mode == "" {
		s.Mode = scoring.ModeEnforce
	}
	s.CreatedAt = fromMS(created)
	return &s, nil
}

func (db *DB) SiteByKey(ctx context.Context, k string) (*store.Site, error) {
	return db.siteWhere(ctx, "site_key=?", k)
}
func (db *DB) SiteBySecretHash(ctx context.Context, h string) (*store.Site, error) {
	return db.siteWhere(ctx, "secret_hash=?", h)
}
func (db *DB) SiteByID(ctx context.Context, id string) (*store.Site, error) {
	return db.siteWhere(ctx, "id=?", id)
}

func (db *DB) ListSites(ctx context.Context) ([]*store.Site, error) {
	rows, err := db.r.QueryContext(ctx, `SELECT id,name,site_key,secret_hash,config,created_at FROM sites ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Site
	for rows.Next() {
		s, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ---------------- nonces ----------------

const nonceCols = `id,site_id,origin,action,seed,issued_at,expires_at,state,ip_hash,ua_hash,pow_salt,pow_bits,pow_n,answer_mac,attempts,event_id,risk,floor`

func (db *DB) Create(ctx context.Context, n *nonce.Nonce) error {
	_, err := db.w.ExecContext(ctx, `INSERT INTO nonces(`+nonceCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		n.ID, n.SiteID, n.Origin, n.Action, n.Seed, ms(n.IssuedAt), ms(n.ExpiresAt), string(n.State),
		n.IPHash, n.UAHash, n.PoWSalt, n.PoWBits, n.PoWN, n.AnswerMAC, n.Attempts, n.EventID, n.Risk, n.Floor)
	return err
}

func scanNonce(row scanner) (*nonce.Nonce, error) {
	var n nonce.Nonce
	var issued, exp int64
	var state string
	err := row.Scan(&n.ID, &n.SiteID, &n.Origin, &n.Action, &n.Seed, &issued, &exp, &state,
		&n.IPHash, &n.UAHash, &n.PoWSalt, &n.PoWBits, &n.PoWN, &n.AnswerMAC, &n.Attempts, &n.EventID, &n.Risk, &n.Floor)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nonce.ErrNotFound
		}
		return nil, err
	}
	n.IssuedAt, n.ExpiresAt, n.State = fromMS(issued), fromMS(exp), nonce.State(state)
	return &n, nil
}

func (db *DB) Get(ctx context.Context, id string) (*nonce.Nonce, error) {
	return scanNonce(db.w.QueryRowContext(ctx, `SELECT `+nonceCols+` FROM nonces WHERE id=?`, id))
}

func (db *DB) Transition(ctx context.Context, id string, from []nonce.State, to nonce.State, now time.Time, mutate func(*nonce.Nonce)) (*nonce.Nonce, error) {
	tx, err := db.w.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	n, err := scanNonce(tx.QueryRowContext(ctx, `SELECT `+nonceCols+` FROM nonces WHERE id=?`, id))
	if err != nil {
		return nil, err
	}
	if !slices.Contains(from, n.State) || !now.Before(n.ExpiresAt) {
		return nil, nonce.ErrWrongState
	}
	n.State = to
	if mutate != nil {
		mutate(n)
	}
	_, err = tx.ExecContext(ctx, `UPDATE nonces SET state=?, expires_at=?, pow_salt=?, pow_bits=?, pow_n=?, answer_mac=?, attempts=?, event_id=?, risk=?, floor=? WHERE id=?`,
		string(n.State), ms(n.ExpiresAt), n.PoWSalt, n.PoWBits, n.PoWN, n.AnswerMAC, n.Attempts, n.EventID, n.Risk, n.Floor, n.ID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return n, nil
}

func (db *DB) PurgeExpired(ctx context.Context, before time.Time) (int64, error) {
	res, err := db.w.ExecContext(ctx, `DELETE FROM nonces WHERE expires_at < ?`, ms(before))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---------------- events ----------------

// featureJSON stores numeric and categorical features. NaN never appears
// because Features drops unknowns.
type featureJSON struct {
	N map[string]float64 `json:"n"`
	C map[string]string  `json:"c"`
}

func (db *DB) InsertEvent(ctx context.Context, e *store.Event) error {
	reasons, _ := json.Marshal(nz(e.Reasons))
	shadow, _ := json.Marshal(nz(e.Shadow))
	num := map[string]float64{}
	for k, v := range e.Features.Num {
		if !math.IsNaN(v) && !math.IsInf(v, 0) {
			num[k] = v
		}
	}
	feats, _ := json.Marshal(featureJSON{N: num, C: e.Features.Cat})
	var chOK any
	if e.ChallengeOK != nil {
		chOK = boolInt(*e.ChallengeOK)
	}
	_, err := db.w.ExecContext(ctx, `INSERT INTO events(id,site_id,ts,action,risk,outcome,would_be,reasons,shadow,shadow_risk,features,fp_hash,ip24_hash,asn,asn_class,country,ua_family,ua_major,os_family,challenge_kind,challenge_ok)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.SiteID, ms(e.TS), e.Action, e.Risk, string(e.Outcome), string(e.WouldBe), string(reasons), string(shadow), e.ShadowRisk,
		string(feats), e.FPHash, e.IP24Hash, e.ASN, e.ASNClass, e.Country, e.UAFamily, e.UAMajor, e.OSFamily, e.ChallengeKind, chOK)
	return err
}

func nz(r []scoring.Reason) []scoring.Reason {
	if r == nil {
		return []scoring.Reason{}
	}
	return r
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (db *DB) UpdateEventChallenge(ctx context.Context, id, kind string, ok bool, risk int, outcome scoring.Outcome, reasons []scoring.Reason) error {
	rj, _ := json.Marshal(nz(reasons))
	_, err := db.w.ExecContext(ctx, `UPDATE events SET challenge_kind=?, challenge_ok=?, risk=?, outcome=?, reasons=? WHERE id=?`,
		kind, boolInt(ok), risk, string(outcome), string(rj), id)
	return err
}

func (db *DB) MarkEventVerified(ctx context.Context, id string, at time.Time) error {
	_, err := db.w.ExecContext(ctx, `UPDATE events SET verified_at=? WHERE id=?`, ms(at), id)
	return err
}

func (db *DB) LabelEvent(ctx context.Context, id, label, source string) error {
	if label != "bot" && label != "human" && label != "" {
		return fmt.Errorf("store: invalid label %q", label)
	}
	res, err := db.w.ExecContext(ctx, `UPDATE events SET label=?, label_source=? WHERE id=?`, label, source, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

const eventCols = `id,site_id,ts,action,risk,outcome,would_be,reasons,shadow,shadow_risk,features,fp_hash,ip24_hash,asn,asn_class,country,ua_family,ua_major,os_family,challenge_kind,challenge_ok,verified_at,label,label_source`

func scanEvent(row scanner) (*store.Event, error) {
	var e store.Event
	var ts int64
	var outcome, wouldBe, reasons, shadow, feats string
	var chOK, verified sql.NullInt64
	err := row.Scan(&e.ID, &e.SiteID, &ts, &e.Action, &e.Risk, &outcome, &wouldBe, &reasons, &shadow, &e.ShadowRisk, &feats,
		&e.FPHash, &e.IP24Hash, &e.ASN, &e.ASNClass, &e.Country, &e.UAFamily, &e.UAMajor, &e.OSFamily, &e.ChallengeKind, &chOK, &verified, &e.Label, &e.LabelSource)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	e.TS, e.Outcome, e.WouldBe = fromMS(ts), scoring.Outcome(outcome), scoring.Outcome(wouldBe)
	_ = json.Unmarshal([]byte(reasons), &e.Reasons)
	_ = json.Unmarshal([]byte(shadow), &e.Shadow)
	var fj featureJSON
	_ = json.Unmarshal([]byte(feats), &fj)
	e.Features = scoring.Features{Num: fj.N, Cat: fj.C}
	if chOK.Valid {
		b := chOK.Int64 == 1
		e.ChallengeOK = &b
	}
	if verified.Valid {
		t := fromMS(verified.Int64)
		e.VerifiedAt = &t
	}
	return &e, nil
}

func (db *DB) GetEvent(ctx context.Context, id string) (*store.Event, error) {
	return scanEvent(db.r.QueryRowContext(ctx, `SELECT `+eventCols+` FROM events WHERE id=?`, id))
}

func (db *DB) ListEvents(ctx context.Context, f store.EventFilter) ([]*store.Event, error) {
	var where []string
	var args []any
	if f.SiteID != "" {
		where, args = append(where, "site_id=?"), append(args, f.SiteID)
	}
	if !f.Since.IsZero() {
		where, args = append(where, "ts>=?"), append(args, ms(f.Since))
	}
	if !f.Until.IsZero() {
		where, args = append(where, "ts<?"), append(args, ms(f.Until))
	}
	if f.Outcome != "" {
		where, args = append(where, "outcome=?"), append(args, string(f.Outcome))
	}
	if f.FPHash != "" {
		where, args = append(where, "fp_hash=?"), append(args, f.FPHash)
	}
	if f.Reason != "" {
		where, args = append(where, `reasons LIKE ?`), append(args, `%"code":"`+f.Reason+`"%`)
	}
	q := `SELECT ` + eventCols + ` FROM events`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q += fmt.Sprintf(" ORDER BY ts DESC LIMIT %d", limit)
	rows, err := db.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (db *DB) DeleteEvent(ctx context.Context, id string) error {
	_, err := db.w.ExecContext(ctx, `DELETE FROM events WHERE id=?`, id)
	return err
}

func (db *DB) PurgeEvents(ctx context.Context, before time.Time) (int64, error) {
	res, err := db.w.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, ms(before))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---------------- replay tracking ----------------

func (db *DB) CanvasSeen(ctx context.Context, siteID, canvasHash, seedHash string, now time.Time, window time.Duration) (bool, error) {
	if canvasHash == "" {
		return false, nil
	}
	tx, err := db.w.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var prevSeed string
	var seenAt int64
	err = tx.QueryRowContext(ctx, `SELECT seed_hash, seen_at FROM canvas_seen WHERE site_id=? AND canvas_hash=?`, siteID, canvasHash).Scan(&prevSeed, &seenAt)
	conflict := false
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return false, err
	default:
		conflict = prevSeed != seedHash && now.Sub(fromMS(seenAt)) < window
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO canvas_seen(site_id,canvas_hash,seed_hash,seen_at) VALUES(?,?,?,?)
		ON CONFLICT(site_id,canvas_hash) DO UPDATE SET seed_hash=excluded.seed_hash, seen_at=excluded.seen_at`,
		siteID, canvasHash, seedHash, ms(now))
	if err != nil {
		return false, err
	}
	return conflict, tx.Commit()
}

// ---------------- lists ----------------

func (db *DB) ListEntries(ctx context.Context, siteID string, now time.Time) ([]store.ListEntry, error) {
	rows, err := db.r.QueryContext(ctx, `SELECT id,site_id,kind,value,action,note,expires_at FROM lists WHERE site_id=? AND (expires_at IS NULL OR expires_at > ?) ORDER BY id`, siteID, ms(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.ListEntry
	for rows.Next() {
		var e store.ListEntry
		var action string
		var exp sql.NullInt64
		if err := rows.Scan(&e.ID, &e.SiteID, &e.Kind, &e.Value, &action, &e.Note, &exp); err != nil {
			return nil, err
		}
		e.Action = scoring.ListAction(action)
		if exp.Valid {
			t := fromMS(exp.Int64)
			e.ExpiresAt = &t
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (db *DB) AddListEntry(ctx context.Context, e *store.ListEntry) error {
	var exp any
	if e.ExpiresAt != nil {
		exp = ms(*e.ExpiresAt)
	}
	res, err := db.w.ExecContext(ctx, `INSERT INTO lists(site_id,kind,value,action,note,expires_at) VALUES(?,?,?,?,?,?)`,
		e.SiteID, e.Kind, e.Value, string(e.Action), e.Note, exp)
	if err != nil {
		return err
	}
	e.ID, _ = res.LastInsertId()
	return nil
}

func (db *DB) DeleteListEntry(ctx context.Context, siteID string, id int64) error {
	_, err := db.w.ExecContext(ctx, `DELETE FROM lists WHERE site_id=? AND id=?`, siteID, id)
	return err
}
