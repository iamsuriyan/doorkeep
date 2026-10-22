-- +goose Up
CREATE TABLE model_state (
  key        TEXT PRIMARY KEY,   -- "hbos:<site>" or "lr:<site>"
  blob       BLOB NOT NULL,
  updated_at INTEGER NOT NULL
);

-- +goose Down
DROP TABLE model_state;
