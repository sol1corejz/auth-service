CREATE TABLE IF NOT EXISTS users
(
    user_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email     TEXT NOT NULL UNIQUE,
    pass_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_email ON users (email);

CREATE TABLE IF NOT EXISTS apps
(
    app_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name   TEXT NOT NULL UNIQUE
);