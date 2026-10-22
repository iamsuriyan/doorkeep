-- +goose Up
CREATE TABLE admin_users (
  name          TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,          -- argon2id PHC string
  created_at    INTEGER NOT NULL
);

CREATE TABLE admin_sessions (
  token_hash TEXT PRIMARY KEY,          -- SHA-256 of the cookie value
  username   TEXT NOT NULL,
  csrf       TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX admin_sessions_exp ON admin_sessions(expires_at);

CREATE TABLE admin_tokens (
  token_hash TEXT PRIMARY KEY,          -- SHA-256 of the bearer token
  name       TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE audit_log (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  ts     INTEGER NOT NULL,
  actor  TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  detail TEXT NOT NULL                  -- JSON
);
CREATE INDEX audit_ts ON audit_log(ts);

CREATE TABLE site_rules (
  site_id    TEXT NOT NULL,
  rule_id    TEXT NOT NULL,
  spec       TEXT NOT NULL,             -- JSON: mode/weight override, or a full custom rule
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (site_id, rule_id)
);

CREATE TABLE aggregates_hourly (
  site_id TEXT NOT NULL,
  hour    INTEGER NOT NULL,             -- unix seconds at the start of the hour
  data    TEXT NOT NULL,                -- JSON counts (outcomes, reasons, countries, ...)
  PRIMARY KEY (site_id, hour)
);

-- +goose Down
DROP TABLE aggregates_hourly;
DROP TABLE site_rules;
DROP TABLE audit_log;
DROP TABLE admin_tokens;
DROP TABLE admin_sessions;
DROP TABLE admin_users;
