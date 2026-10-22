-- +goose Up
CREATE TABLE model_state (
  key        TEXT PRIMARY KEY,   -- "hbos:<site>" or "lr:<site>"
  blob       BYTEA NOT NULL,
  updated_at BIGINT NOT NULL
);

-- +goose Down
DROP TABLE model_state;
