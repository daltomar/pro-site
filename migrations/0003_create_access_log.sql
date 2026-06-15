CREATE TABLE access_log (
    id           BIGSERIAL PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    username     TEXT NOT NULL,
    accessed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address   TEXT
);
