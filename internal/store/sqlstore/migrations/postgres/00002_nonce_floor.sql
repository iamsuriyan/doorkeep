-- +goose Up
ALTER TABLE nonces ADD COLUMN floor BIGINT NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE nonces DROP COLUMN floor;
