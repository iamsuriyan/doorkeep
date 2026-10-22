-- +goose Up
CREATE TABLE sites (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  site_key      TEXT NOT NULL UNIQUE,
  secret_hash   TEXT NOT NULL UNIQUE,
  config        TEXT NOT NULL,           -- JSON: origins, thresholds, mode, actions, ...
  created_at    INTEGER NOT NULL
);

CREATE TABLE nonces (
  id          TEXT PRIMARY KEY,
  site_id     TEXT NOT NULL,
  origin      TEXT NOT NULL,
  action      TEXT NOT NULL,
  seed        TEXT NOT NULL,
  issued_at   INTEGER NOT NULL,          -- unix ms
  expires_at  INTEGER NOT NULL,          -- unix ms
  state       TEXT NOT NULL,
  ip_hash     TEXT NOT NULL,
  ua_hash     TEXT NOT NULL,
  pow_salt    TEXT NOT NULL DEFAULT '',
  pow_bits    INTEGER NOT NULL DEFAULT 0,
  pow_n       INTEGER NOT NULL DEFAULT 0,
  answer_mac  TEXT NOT NULL DEFAULT '',
  attempts    INTEGER NOT NULL DEFAULT 0,
  event_id    TEXT NOT NULL DEFAULT '',
  risk        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX nonces_expires ON nonces(expires_at);

CREATE TABLE events (
  id             TEXT PRIMARY KEY,
  site_id        TEXT NOT NULL,
  ts             INTEGER NOT NULL,       -- unix ms
  action         TEXT NOT NULL,
  risk           INTEGER NOT NULL,
  outcome        TEXT NOT NULL,
  would_be       TEXT NOT NULL,
  reasons        TEXT NOT NULL,          -- JSON
  shadow         TEXT NOT NULL,          -- JSON
  shadow_risk    INTEGER NOT NULL,
  features       TEXT NOT NULL,          -- JSON, bucketed only
  fp_hash        TEXT NOT NULL,
  ip24_hash      TEXT NOT NULL,
  asn            INTEGER NOT NULL DEFAULT 0,
  asn_class      TEXT NOT NULL DEFAULT '',
  country        TEXT NOT NULL DEFAULT '',
  ua_family      TEXT NOT NULL DEFAULT '',
  ua_major       INTEGER NOT NULL DEFAULT 0,
  os_family      TEXT NOT NULL DEFAULT '',
  challenge_kind TEXT NOT NULL DEFAULT '',
  challenge_ok   INTEGER,                -- NULL = no challenge
  verified_at    INTEGER,
  label          TEXT NOT NULL DEFAULT '',
  label_source   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX events_site_ts ON events(site_id, ts);
CREATE INDEX events_site_fp ON events(site_id, fp_hash);

CREATE TABLE canvas_seen (
  site_id     TEXT NOT NULL,
  canvas_hash TEXT NOT NULL,
  seed_hash   TEXT NOT NULL,
  seen_at     INTEGER NOT NULL,
  PRIMARY KEY (site_id, canvas_hash)
);

CREATE TABLE lists (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id     TEXT NOT NULL,
  kind        TEXT NOT NULL,
  value       TEXT NOT NULL,
  action      TEXT NOT NULL,
  note        TEXT NOT NULL DEFAULT '',
  expires_at  INTEGER
);
CREATE INDEX lists_site ON lists(site_id);

-- +goose Down
DROP TABLE lists;
DROP TABLE canvas_seen;
DROP TABLE events;
DROP TABLE nonces;
DROP TABLE sites;
