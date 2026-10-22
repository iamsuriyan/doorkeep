-- +goose Up
-- Purges filter on these columns alone; without an index they scan the table.
CREATE INDEX canvas_seen_at ON canvas_seen(seen_at);
CREATE INDEX events_ts ON events(ts);

-- Admin bearer tokens expire and can be listed and revoked by id (a prefix
-- of the hash; the token itself is never stored).
ALTER TABLE admin_tokens ADD COLUMN expires_at INTEGER;
ALTER TABLE admin_tokens ADD COLUMN last_used_at INTEGER;

-- Small key/value state, e.g. the rollup high-water mark.
CREATE TABLE kv (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- +goose Down
DROP TABLE kv;
ALTER TABLE admin_tokens DROP COLUMN last_used_at;
ALTER TABLE admin_tokens DROP COLUMN expires_at;
DROP INDEX events_ts;
DROP INDEX canvas_seen_at;
