-- Initial schema — SQLite-first. Postgres variant lives in a separate
-- `migrations/postgres/` dir when we add it (see DECISIONS.md D21).
--
-- UUID columns use BLOB storage because sqlx's default Uuid encoder on SQLite
-- is 16-byte binary. We keep the benefits of native Uuid types on the Rust
-- side without string conversions.

CREATE TABLE organizations (
    id          BLOB    PRIMARY KEY,
    name        TEXT    NOT NULL,
    slug        TEXT    NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL
);

CREATE TABLE users (
    id          BLOB    PRIMARY KEY,
    github_id   INTEGER NOT NULL UNIQUE,
    login       TEXT    NOT NULL,
    email       TEXT,
    name        TEXT,
    avatar_url  TEXT,
    created_at  INTEGER NOT NULL
);

CREATE TABLE org_members (
    org_id      BLOB    NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id     BLOB    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (org_id, user_id)
);

CREATE TABLE api_tokens (
    id            BLOB    PRIMARY KEY,
    org_id        BLOB    NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id       BLOB    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT    NOT NULL,
    hashed_token  TEXT    NOT NULL UNIQUE,
    scopes        TEXT    NOT NULL,
    last_used_at  INTEGER,
    expires_at    INTEGER,
    created_at    INTEGER NOT NULL
);

CREATE INDEX api_tokens_by_org ON api_tokens(org_id);

CREATE TABLE reservations (
    id          BLOB    PRIMARY KEY,
    org_id      BLOB    NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    label       TEXT    NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL
);

CREATE INDEX reservations_by_org ON reservations(org_id);

CREATE TABLE tunnels (
    id             BLOB    PRIMARY KEY,
    org_id         BLOB    NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind           TEXT    NOT NULL,
    hostname       TEXT    NOT NULL,
    state          TEXT    NOT NULL,
    labels_json    TEXT    NOT NULL DEFAULT '[]',
    inspect        INTEGER NOT NULL DEFAULT 1,
    created_at     INTEGER NOT NULL,
    last_seen_at   INTEGER NOT NULL
);

CREATE INDEX tunnels_by_hostname ON tunnels(hostname);
CREATE INDEX tunnels_by_org ON tunnels(org_id);

CREATE TABLE certs (
    id                  BLOB    PRIMARY KEY,
    hostname            TEXT    NOT NULL,
    not_after           INTEGER NOT NULL,
    cert_chain_pem      TEXT    NOT NULL,
    key_pem_encrypted   TEXT    NOT NULL,
    created_at          INTEGER NOT NULL
);

CREATE INDEX certs_by_hostname ON certs(hostname);

CREATE TABLE custom_domains (
    id                   BLOB    PRIMARY KEY,
    org_id               BLOB    NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    hostname             TEXT    NOT NULL UNIQUE,
    verification_token   TEXT    NOT NULL,
    verified_at          INTEGER,
    cert_id              BLOB    REFERENCES certs(id) ON DELETE SET NULL,
    created_at           INTEGER NOT NULL
);

CREATE TABLE inspection_captures (
    id                BLOB    PRIMARY KEY,
    tunnel_id         BLOB    NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
    request_id        BLOB    NOT NULL,
    started_at        INTEGER NOT NULL,
    completed_at      INTEGER,
    method            TEXT    NOT NULL,
    path              TEXT    NOT NULL,
    status            INTEGER,
    duration_ms       INTEGER,
    req_headers_json  TEXT    NOT NULL DEFAULT '[]',
    req_body          BLOB,
    resp_headers_json TEXT,
    resp_body         BLOB,
    truncated         INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX inspection_by_tunnel_started ON inspection_captures(tunnel_id, started_at DESC);

CREATE TABLE audit_events (
    id              BLOB    PRIMARY KEY,
    org_id          BLOB    NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_user_id   BLOB    REFERENCES users(id) ON DELETE SET NULL,
    kind            TEXT    NOT NULL,
    payload_json    TEXT    NOT NULL DEFAULT '{}',
    created_at      INTEGER NOT NULL
);

CREATE INDEX audit_by_org_created ON audit_events(org_id, created_at DESC);

CREATE TABLE sessions (
    id          BLOB    PRIMARY KEY,
    user_id     BLOB    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id      BLOB    NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    expires_at  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE INDEX sessions_by_user ON sessions(user_id);
