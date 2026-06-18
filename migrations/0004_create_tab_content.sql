CREATE TABLE tab_content (
    tab_number    SMALLINT PRIMARY KEY CHECK (tab_number BETWEEN 1 AND 4),
    body_text     TEXT,
    image_filename TEXT,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
