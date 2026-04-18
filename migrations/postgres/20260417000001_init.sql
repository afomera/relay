-- Postgres port of the initial schema. Kept structurally identical to the
-- SQLite variant under ../sqlite/ — type names differ but columns, FKs,
-- defaults, and indexes line up 1:1 so the DAL stays portable.
--
-- Type mapping (see DECISIONS.md D3/D22/D23 + the Postgres plan):
--   BLOB  PRIMARY KEY     -> UUID    PRIMARY KEY   (native UUID, sqlx-compatible)
--   INTEGER (epoch)       -> BIGINT                (i64 seconds since 1970-01-01Z)
--   INTEGER flag          -> BOOLEAN               (inspect, truncated)
--   BLOB (body)           -> BYTEA                 (req/resp body buffers)
--   TEXT                  -> TEXT

CREATE TABLE organizations (
    id          UUID    PRIMARY KEY,
    name        TEXT    NOT NULL,
    slug        TEXT    NOT NULL UNIQUE,
    created_at  BIGINT  NOT NULL
);

CREATE TABLE users (
    id          UUID    PRIMARY KEY,
    github_id   BIGINT  NOT NULL UNIQUE,
    login       TEXT    NOT NULL,
    email       TEXT,
    name        TEXT,
    avatar_url  TEXT,
    created_at  BIGINT  NOT NULL
);

CREATE TABLE org_members (
    org_id      UUID    NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id     UUID    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT    NOT NULL,
    created_at  BIGINT  NOT NULL,
    PRIMARY KEY (org_id, user_id)
);

CREATE TABLE api_tokens (
    id            UUID    PRIMARY KEY,
    org_id        UUID    NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id       UUID    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT    NOT NULL,
    hashed_token  TEXT    NOT NULL UNIQUE,
    scopes        TEXT    NOT NULL,
    last_used_at  BIGINT,
    expires_at    BIGINT,
    created_at    BIGINT  NOT NULL
);

CREATE INDEX api_tokens_by_org ON api_tokens(org_id);

CREATE TABLE reservations (
    id          UUID    PRIMARY KEY,
    org_id      UUID    NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    label       TEXT    NOT NULL UNIQUE,
    created_at  BIGINT  NOT NULL
);

CREATE INDEX reservations_by_org ON reservations(org_id);

CREATE TABLE tunnels (
    id             UUID    PRIMARY KEY,
    org_id         UUID    NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind           TEXT    NOT NULL,
    hostname       TEXT    NOT NULL,
    state          TEXT    NOT NULL,
    labels_json    TEXT    NOT NULL DEFAULT '[]',
    inspect        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at     BIGINT  NOT NULL,
    last_seen_at   BIGINT  NOT NULL
);

CREATE INDEX tunnels_by_hostname ON tunnels(hostname);
CREATE INDEX tunnels_by_org ON tunnels(org_id);

CREATE TABLE certs (
    id                  UUID    PRIMARY KEY,
    hostname            TEXT    NOT NULL,
    not_after           BIGINT  NOT NULL,
    cert_chain_pem      TEXT    NOT NULL,
    key_pem_encrypted   TEXT    NOT NULL,
    created_at          BIGINT  NOT NULL
);

CREATE INDEX certs_by_hostname ON certs(hostname);

CREATE TABLE custom_domains (
    id                   UUID    PRIMARY KEY,
    org_id               UUID    NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    hostname             TEXT    NOT NULL UNIQUE,
    verification_token   TEXT    NOT NULL,
    verified_at          BIGINT,
    cert_id              UUID    REFERENCES certs(id) ON DELETE SET NULL,
    created_at           BIGINT  NOT NULL
);

CREATE TABLE inspection_captures (
    id                UUID    PRIMARY KEY,
    tunnel_id         UUID    NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
    request_id        UUID    NOT NULL,
    started_at        BIGINT  NOT NULL,
    completed_at      BIGINT,
    method            TEXT    NOT NULL,
    path              TEXT    NOT NULL,
    status            BIGINT,
    duration_ms       BIGINT,
    req_headers_json  TEXT    NOT NULL DEFAULT '[]',
    req_body          BYTEA,
    resp_headers_json TEXT,
    resp_body         BYTEA,
    truncated         BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX inspection_by_tunnel_started ON inspection_captures(tunnel_id, started_at DESC);

CREATE TABLE audit_events (
    id              UUID    PRIMARY KEY,
    org_id          UUID    NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_user_id   UUID    REFERENCES users(id) ON DELETE SET NULL,
    kind            TEXT    NOT NULL,
    payload_json    TEXT    NOT NULL DEFAULT '{}',
    created_at      BIGINT  NOT NULL
);

CREATE INDEX audit_by_org_created ON audit_events(org_id, created_at DESC);

CREATE TABLE sessions (
    id          UUID    PRIMARY KEY,
    user_id     UUID    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id      UUID    NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    expires_at  BIGINT  NOT NULL,
    created_at  BIGINT  NOT NULL
);

CREATE INDEX sessions_by_user ON sessions(user_id);
