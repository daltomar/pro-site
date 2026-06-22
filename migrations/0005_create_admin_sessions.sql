CREATE TABLE admin_sessions (
    token_hash  TEXT        PRIMARY KEY,
    expires_at  TIMESTAMPTZ NOT NULL
);
