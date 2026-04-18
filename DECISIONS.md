# Implementation decisions

Each entry records a design choice made during implementation where the spec left room. Entries are append-only — if we change course later, add a new entry instead of rewriting.

## D1 — QUIC ALPN: `relay/1`

The CLI↔edge QUIC connection advertises ALPN `relay/1`. Bumping the protocol major becomes `relay/2`.

**Rationale:** lets the edge share :443/UDP with future protocols and gives a clean version negotiation point.

## D2 — Stream framing: length-prefixed CBOR, `u32` LE prefix

Every message on a QUIC stream is `[u32 length (little-endian)] [CBOR payload]`. 16 MiB maximum per frame.

**Rationale:** stream-aware (unlike reading-to-EOF), self-describing, no alignment surprises. u32 is plenty; single frames are always small — request/response bodies stream as raw bytes *after* the header frame, not as CBOR.

## D3 — HTTP body transport: raw bytes after the header frame

`HttpRequestHeader` / `HttpResponseHeader` are framed CBOR; the body is raw bytes on the same QUIC stream until the peer calls `finish()`. No chunked framing.

**Rationale:** QUIC streams already give us reliable-ordered-framed bytes with clean EOF via `finish`. Re-framing would just add copies.

## D4 — Development TLS: self-signed wildcard with CLI trust-on-first-use

In dev mode (`--dev` on `relayd`), the server generates a self-signed cert for the configured base domain at startup and writes its public cert to `~/.relayd/dev-cert.pem`. The CLI has `--insecure` and `--cafile` flags to accept it.

**Rationale:** avoids requiring a real ACME run just to `cargo run` the stack. Production deploys use the real wildcard cert via ACME (§6 of SPEC).

## D5 — Temporary hostnames: `<adj>-<noun>-<4 hex>`

Random hostnames follow `<adjective>-<noun>-<4hex>` (e.g. `bright-otter-a9f2`). Wordlists live in `relay-edge/src/wordlists.rs` — short-adjective + short-noun, ~300 of each, for ~3.6M combos before the hex suffix. Full hostname: `bright-otter-a9f2.temporary.<base-domain>`.

**Rationale:** memorable-ish for a dev session, unambiguous in URLs, collision-safe with the hex suffix.

## D6 — Port layout (dev defaults)

| Port   | Purpose                                   |
|--------|-------------------------------------------|
| 7080   | HTTP public ingress (plain HTTP in dev)   |
| 7443   | HTTPS public ingress                      |
| 7443   | QUIC (UDP, same port)                     |
| 7090   | Control plane (API + dashboard)           |
| 29000-29999 | TCP tunnel port pool                 |

Production config binds `:80`, `:443` (TCP+UDP), and puts the dashboard behind an internal-only port.

**Rationale:** lets a developer run the whole stack without sudo.

## D7 — UUIDs: TEXT on SQLite, UUID on Postgres, string-serialized on the wire

`sqlx::types::Uuid` already handles both. In the wire protocol UUIDs serialize as strings (not byte arrays) for readability and cross-language compatibility.

**Rationale:** matches common HTTP API conventions and avoids endian debates.

## D8 — Session storage: `tower-sessions` + DB-backed store

Dashboard uses signed, encrypted session cookies with server-side storage in a `sessions` table. Key derived from `RELAY_DATA_KEY`.

**Rationale:** standard axum ecosystem; gives us session invalidation (logout) for free.

## D9 — Cert key encryption at rest: AES-GCM-SIV

Private key PEM is encrypted with AES-GCM-SIV under a 32-byte key read from `RELAY_DATA_KEY` (base64). Nonce stored alongside ciphertext.

**Rationale:** SIV is nonce-misuse-resistant, which matters because we key rotation is not yet in scope. Users who lose `RELAY_DATA_KEY` lose their certs — acceptable; they're re-issuable.

## D10 — Auto-created personal org on first login

Every new GitHub login creates an `organizations` row with `name = "<github_login>'s org"`, `slug = <github_login>`, and an `org_members` row with role `owner`. All user-owned resources FK to org, not user.

**Rationale:** future multi-user orgs don't need a data migration.

## D11 — Reservation scoping: single-label only in v1

Reservations are single DNS labels (`andrea`) — no dotted paths. A reservation for `andrea` covers every subtree leaf under `*.andrea.<base>`. No way to reserve a sub-path like `api.andrea` on its own.

**Rationale:** matches the user requirement and keeps lookup to a single table scan.

## D12 — Inspection capture limits: 1 MiB bodies, 7 day retention

Per-direction body cap: 1,048,576 bytes. Beyond that: `truncated = true` and we stop buffering (bytes still flow through the tunnel).

A background job in `relay-control` deletes rows older than 7 days every hour.

**Rationale:** lets the inspector work for typical API payloads without a memory or disk blowout. Tunable via config.

## D13 — HTTP inspector: per-tunnel opt-in, default on in HTTP mode

The spec says inspection is opt-in. Implementation default: **on** for `relay http`, **off** for `relay tcp`/`relay tls` (we can't see inside raw TCP or TLS passthrough anyway). CLI `--no-inspect` disables it.

**Rationale:** the inspector is the killer feature; off-by-default hides it from new users.

## D14 — Dashboard JS: HTMX + a few lines of vanilla JS

No build step. HTMX (via CDN or vendored single file) handles form posts and live partials. SSE via EventSource for the live request tail. Styling: Pico CSS or similar no-build classless framework.

**Rationale:** spec §4 picked axum + Askama; avoiding a bundler keeps the self-host story to "one binary + static assets baked into it."

## D15 — Static assets baked into the binary

`askama` templates compile into the binary. CSS/JS live in `crates/relay-control/assets/` and are embedded with `rust-embed`, served from `/_static/`.

**Rationale:** aligned with §11 of SPEC — single static binary for self-host.

## D16 — Random hostname collisions: retry N times, then 503

If an temporary name collides with an already-active tunnel, retry 5 times. With 3.6M combos and typical concurrency this should never happen. If it does, the CLI gets a clear error.

**Rationale:** probabilistic OK; alternative (sequential counters) leaks tunnel volume.

## D17 — WebSocket support: detect upgrade, switch to raw byte copy

Under the same `TunnelKind::Http` tunnel, each request starts as a normal HTTP/1.1 exchange. Both ends inspect the request headers — if `Connection: upgrade` + `Upgrade: websocket` are present, they branch:

- **Edge** captures `hyper::upgrade::OnUpgrade` from the request, skips the usual request-body forwarder (upgrade requests have no body in the HTTP/1.1 sense), reads the `HttpResponseHeader` frame from the CLI, and — on `101 Switching Protocols` — preserves `Connection`/`Upgrade` on the response, returns the 101, then spawns a bidirectional byte-copy task between the `Upgraded` IO and the QUIC bidi stream.
- **CLI** opens a raw TCP socket to the local port, hand-rolls the HTTP/1.1 request, parses the response status + headers with `httparse`, forwards them via `HttpResponseHeader`, and does the same bidi copy between local TCP and QUIC.

Both sides propagate half-close: QUIC-recv EOF triggers a write-half shutdown on the peer socket, so browsers don't hang waiting for bytes that will never come.

Only HTTP/1.1 is supported. RFC 8441 (WS over h2, extended CONNECT) is not implemented — browsers default to h1 for WS handshakes unless the server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`, which we don't.

Plain HTTP ingress uses a manual `serve_connection_with_upgrades` accept loop (mirror of the HTTPS ingress). `axum::serve` uses `serve_connection` without upgrade support, so we bypass it.

**Rationale:** there is no way to tunnel WebSockets through a high-level HTTP client (`reqwest`) — once the 101 is returned, the underlying socket must be surrendered for raw I/O. The CLI hand-rolls HTTP/1.1 only for the upgrade path; non-upgrade traffic still goes through `reqwest` unchanged.

## D18 — QUIC idle timeout: 30 seconds; keepalive every 10 seconds

CLI sends a `Ping` control-stream frame every 10s; server resets idle timeout on any frame. Idle > 30s → connection closed.

**Rationale:** detects dead NAT mappings and hung CLIs without excess traffic.

## D19 — Single-binary self-host packaging

`relayd` binary embeds both edge and control code. A future hosted deployment can split them by running two instances with different config flags (`--role edge` / `--role control`).

**Rationale:** simplest self-host experience; spec §3 already flagged this.

## D20 — `relay-acme` uses `instant-acme` + `rcgen`

Standing on `instant-acme` for ACME protocol + `rcgen` for CSR generation. No vendored ACME logic.

**Rationale:** these are the maintained, minimal, rustls-compatible options.

## D21 — v1 ships SQLite only; Postgres is a typed stub

`relay-db` is fronted by an `AnyPool` abstraction, but v1 only implements the
SQLite backend. Postgres variants compile but return `unimplemented!` — flipping
them on is a schema-port + query-rewrite project, not a fundamental change.

**Rationale:** supporting both drivers through `sqlx::Any` loses compile-time
query checking and `time::OffsetDateTime` native binding. Shipping one backend
first keeps the DAL sharp; the second is additive. Self-hosters who need
Postgres get a clear "not yet" rather than a half-broken surface.

## D22 — Timestamps: `INTEGER` unix seconds

All `*_at` columns are `INTEGER NOT NULL` storing seconds since epoch. The
domain layer converts to/from `time::OffsetDateTime` at the edge of the DAL.

**Rationale:** trivially portable across SQLite and Postgres, orderable with
plain `<`, no serialization ambiguity, no TZ confusion. Human readability is
lost at the raw-row level but the dashboard renders them anyway.

## D23 — IDs: BLOB UUIDs in SQLite, UUID in Postgres

UUID columns in the SQLite migration are `BLOB PRIMARY KEY` (16 raw bytes),
which is what `sqlx::types::Uuid` encodes to on SQLite. The future Postgres
migration will use the native `UUID` type.

**Rationale:** we tried `TEXT` first; `sqlx` decodes `Uuid` from `TEXT` only if
the column holds the 16-byte binary form, which defeats the point. `BLOB` gives
us round-trip-correct native `Uuid` in Rust with no newtype wrapper.

## D24 — Postgres backend landed (supersedes D21's "typed stub")

Postgres is now a first-class backend alongside SQLite. The stub behaviour D21
documented no longer exists.

**Architecture:**

- `Db` is a two-variant enum (`Sqlite(SqlitePool)`, `Postgres(PgPool)`).
- Per-engine DAL fns live under `crates/relay-db/src/backend/{sqlite,postgres}.rs`
  with byte-identical signatures. Each crate-root dispatcher (`relay_db::foo`)
  matches on the enum and forwards to the right backend.
- `sqlx::Any` is deliberately rejected, same reasons as D21 — we keep native
  typed bindings on both sides, including `Uuid`, `bool`, and `i64`.
- Migrations live in two compile-time-embedded directories
  (`migrations/sqlite/` and `migrations/postgres/`), dispatched by
  `Db::migrate`. Single-binary self-host (D15) is preserved.

**Schema type mapping:**

| Concept | SQLite | Postgres |
|---|---|---|
| Primary/foreign UUID | `BLOB` | `UUID` |
| Unix-epoch timestamp (`*_at`) | `INTEGER` (i64) | `BIGINT` (i64) |
| Flag column (`inspect`, `truncated`) | `INTEGER` 0/1 | `BOOLEAN` |
| Body buffer (`req_body`, `resp_body`) | `BLOB` | `BYTEA` |
| JSON-shaped (`*_json`) | `TEXT` | `TEXT` — no JSONB for now |

**Rationale for sticking with `TEXT` for JSON:** no JSON querying in the DAL
today, and keeping the serialization path identical on both engines avoids an
encoding split. JSONB is easy to add later without a schema break.

**Managed-service friendliness:** sqlx pulls in `tls-rustls-ring-webpki`, so
the driver talks TLS to PlanetScale Postgres / Neon / Crunchy / Fly without
needing the system trust store. `[db]` grows `url_env`, `max_connections`,
and `acquire_timeout_secs`; `url_env` takes precedence over `url` so PaaS
deploys don't commit a `DATABASE_URL` to config. Prod currently runs
PlanetScale Postgres 18.3.
