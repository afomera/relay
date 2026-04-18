# Relay — v1 Specification

> A Rust-based tunneling CLI and service. Open-source (MIT), designed for easy enterprise self-hosting.

## 1. Goals

- Secure public URLs for local services (HTTP/HTTPS, raw TCP, WebSocket).
- Single static binary on both sides (`relay` CLI, `relayd` server).
- Self-hostable with no more than a Postgres/SQLite DB and a DNS API token.
- Hosted service at `withrelay.dev` (marketing) with tunnels at `*.sharedwithrelay.com`.
- Custom-domain support from day one (`tunnel.mycompany.com`).

## 2. Non-goals (v1)

- UDP tunneling (WebRTC/game servers). Deferred.
- Multi-region / anycast. Single region, plan for future split.
- Billing, quotas, rate limits beyond basic per-account caps.
- SAML/OIDC SSO (GitHub OAuth only for v1).
- Mobile apps, IDE plugins.

## 3. High-level architecture

```
┌──────────┐    QUIC (TLS 1.3)     ┌──────────────────────────┐
│  relay   │◄─────────────────────►│         relayd           │
│  (CLI)   │  control + per-req    │  ┌──────────┐┌────────┐  │
└────┬─────┘  bidi streams         │  │   edge   ││control │  │
     │                             │  │ (ingress)││(API+UI)│  │
   local                           │  └────┬─────┘└───┬────┘  │
   service                         │       │          │       │
                                   └───────┼──────────┼───────┘
                                           │          │
                               ┌───────────▼──┐   ┌───▼────────┐
                  HTTPS/TCP    │  Public       │   │  Postgres  │
                  from users ─►│  listeners    │   │  or SQLite │
                               │  :443 / :tcp  │   └────────────┘
                               └───────────────┘
```

- **CLI (`relay`)**: opens a QUIC connection to the edge, authenticates with an API token, registers hostnames (or requests random ones), proxies per-request streams to the user's local service.
- **Edge**: terminates TLS for `*.sharedwithrelay.com` + registered custom domains, looks up the active tunnel by hostname, opens a per-request bidi QUIC stream to the corresponding CLI, streams bytes.
- **Control plane**: axum HTTP API + server-rendered dashboard (Askama + HTMX). Owns accounts, orgs, tokens, reservations, custom domains, certs, inspection captures.
- **DB**: `sqlx` with matching migrations that run on SQLite and Postgres.

At v1, edge + control run in one `relayd` process. They are separate library crates so a future hosted deployment can split them.

## 4. Wire protocol (CLI ↔ edge)

Transport: **QUIC** (quinn). TLS 1.3 is mandatory, edge presents a cert for its own hostname (`edge.sharedwithrelay.com`); CLI verifies normally.

On connect the CLI opens one **control stream** (bidi, stream id 0 by convention) and sends:

```
ClientHello {
  protocol_version: u16,
  auth_token: String,
  client_version: String,   // relay CLI version
  os: String, arch: String, // telemetry
}
```

Server replies:

```
ServerHello {
  protocol_version: u16,
  account_id: Uuid,
  features: Vec<Feature>,  // e.g. Inspection, TcpTunnels, CustomDomains
}
```

Then the CLI registers tunnels:

```
RegisterTunnel {
  req_id: Uuid,
  kind: Http | Tcp | TlsPassthrough,
  hostname: Option<String>,     // e.g. "andrea", "foo.andrea", or "tunnel.mycompany.com"
  labels: Vec<(String,String)>, // freeform, shown in UI
}
```

Server replies `TunnelRegistered { req_id, tunnel_id, public_url }` or `TunnelRejected { req_id, reason }`.

When a public request arrives, the **edge** opens a new bidi stream to the CLI and writes a `RequestHeader`:

```
// HTTP tunnels
HttpRequestHeader {
  tunnel_id: Uuid,
  request_id: Uuid,
  method: String,
  path: String,
  headers: Vec<(String,String)>,
  remote_ip: IpAddr,
  tls: bool,
}
// followed by request body bytes until stream finish
// CLI writes HttpResponseHeader + body bytes back on same stream

// TCP/TLS-passthrough tunnels
TcpConnectHeader { tunnel_id, connection_id, remote_ip }
// then raw bytes both ways until close
```

Headers are **CBOR** (or postcard) — small, schema-ful, easy to evolve via versioned enums. Never JSON on the hot path.

Request inspection (§9) is opt-in; when enabled the edge also forks a copy of header/body bytes into the control-plane capture sink.

## 5. Routing & subdomain model

### 5.1 Hosted (`*.sharedwithrelay.com`)

Reservation rules:

- Any authed user may reserve a root label — e.g. `andrea`.
- A reservation implies ownership of the entire subtree: `andrea.sharedwithrelay.com`, `admin.andrea.sharedwithrelay.com`, `api.andrea.sharedwithrelay.com`, etc.
- The owner may bind any single tunnel to any leaf under their reservation. Multiple leaves can run simultaneously (separate tunnels for `api.andrea` and `admin.andrea`).
- Random hostnames (when user doesn't reserve anything) are generated under a shared pool like `<slug>.temporary.sharedwithrelay.com`. Short TTL — freed when the tunnel closes.

Routing lookup on ingress (host header or SNI):

1. Strip the base domain (`sharedwithrelay.com`). Remainder: `api.andrea`.
2. Iterate labels right-to-left until a reservation hit: `andrea` → reservation for account X.
3. Ask the edge's in-memory tunnel registry for an active session matching that hostname exactly. If none, 502 branded page.
4. Open per-request stream to that session.

### 5.2 Custom domains

User flow:

1. Dashboard: "Add domain" → user enters `tunnel.mycompany.com`.
2. We generate a random verification value; user creates `_relay-challenge.tunnel.mycompany.com` TXT with that value AND `tunnel.mycompany.com` CNAME to their reservation apex (e.g. `andrea.sharedwithrelay.com`).
3. Dashboard "Verify" button: we resolve TXT, confirm match, mark domain verified.
4. We issue a cert via ACME **HTTP-01** (we control the HTTP path now that traffic is CNAME'd to us).
5. Routing: custom_domain table is consulted before the `sharedwithrelay.com` logic.

No wildcard issuance for customer domains in v1.

## 6. TLS / certificates

- `*.sharedwithrelay.com` wildcard cert: ACME **DNS-01** via pluggable `DnsProvider`.
- Custom domains: ACME **HTTP-01**, served by the edge on port 80.
- Cert store: rows in DB (`certs` table: `hostname`, `cert_chain_pem`, `key_pem_encrypted`, `not_after`), cached in memory on each edge process. Keys encrypted at rest using a key-encryption-key supplied via env (`RELAY_DATA_KEY`).
- Renewal worker: runs inside `relayd`, checks `not_after < now + 30d` every hour.

`relay-dns` crate implementations for v1: **Cloudflare**, **Route53**, **RFC2136** (dynamic DNS). Selected via config.

## 7. Auth

- **Dashboard login**: GitHub OAuth only.
- **CLI auth**: user generates API token from dashboard → `relay auth login --token <t>` stores it in `~/.config/relay/config.toml` (or equivalent per-OS).
- Tokens: random 32-byte values, prefixed (`rly_pat_...` for personal access tokens), stored hashed (argon2id) in DB. Token metadata: `name`, `scopes`, `last_used_at`, `expires_at` optional.
- Each QUIC handshake carries a token; bad token = hard close.
- v1 scopes: `tunnels:create`, `tunnels:manage`, `domains:manage`. No org-admin scopes yet.

## 8. Data model (sketch)

Schemas match on SQLite and Postgres via `sqlx`. IDs are UUIDs (stored as BLOB on SQLite, UUID on Postgres — see DECISIONS.md D23).

```
organizations (id, name, slug, created_at)
users (id, github_id, email, name, avatar_url, created_at)
org_members (org_id, user_id, role, created_at)        -- v1: every user gets a personal org, role='owner'
api_tokens (id, org_id, user_id, name, hashed_token, scopes, last_used_at, expires_at, created_at)
reservations (id, org_id, label, created_at, UNIQUE(label))
  -- label = "andrea"; implies *.andrea.sharedwithrelay.com
tunnels (id, org_id, kind, hostname, state, created_at, last_seen_at)
  -- state: pending|active|disconnected
custom_domains (id, org_id, hostname, verification_token, verified_at, cert_id, created_at, UNIQUE(hostname))
certs (id, hostname, not_after, cert_chain_pem, key_pem_encrypted, created_at)
inspection_captures (id, tunnel_id, request_id, started_at, completed_at,
                     method, path, status, duration_ms,
                     req_headers_json, req_body_blob, resp_headers_json, resp_body_blob,
                     truncated bool)
audit_events (id, org_id, actor_user_id, kind, payload_json, created_at)
```

Notes:

- `organizations` scaffold from day 1 — every new user auto-creates a personal org; multi-user orgs are deferred but the FK columns exist.
- `inspection_captures` body blobs capped (e.g. 1 MiB each); `truncated=true` above that. Retention job trims after N days.

## 9. Request inspection

- Per-tunnel toggle: `--inspect` flag on CLI, or default-on for HTTP.
- Edge forks header+body bytes into a bounded async channel → control-plane writer batches into DB.
- Dashboard tunnel detail page shows a table of recent requests, click-through to full headers + body (rendered with content-type aware viewer: JSON pretty, image inline, binary hex).
- Replay: dashboard issues a new request to the same tunnel with stored payload. (Stretch goal for v1.)
- Live tail: SSE endpoint streams new capture rows to the dashboard while the page is open.

## 10. CLI surface (v1)

```
relay auth login --token <t>
relay auth logout
relay auth status

relay http <port>                       # random hostname
relay http <port> --hostname api.andrea # uses reservation
relay http <port> --domain tunnel.mycompany.com

relay tcp <port>                        # assigns a TCP port on the edge
relay tls <port> --hostname ...         # TLS passthrough

relay tunnels list
relay tunnels stop <id>

relay domains list
relay domains add tunnel.mycompany.com
relay domains verify tunnel.mycompany.com

relay reservations list
relay reservations add andrea
```

Config: `~/.config/relay/config.toml`, env overrides, `--server` flag for pointing at a self-hosted instance.

## 11. `relayd` server binary

Single static binary. Config via TOML + env.

```toml
# /etc/relay/relayd.toml
[server]
bind_http = "0.0.0.0:80"
bind_https = "0.0.0.0:443"
bind_quic = "0.0.0.0:443"        # QUIC shares :443 UDP
bind_admin = "127.0.0.1:7080"    # dashboard + API, put behind own proxy

[domains]
base = "sharedwithrelay.com"
temporary = "temporary.sharedwithrelay.com"

[dns]
provider = "cloudflare"          # cloudflare | route53 | rfc2136
# provider-specific config below

[db]
# Pick one. Managed-Postgres deploys usually set url_env = "DATABASE_URL".
url = "sqlite:///var/lib/relay/relay.db"   # or postgres://user:pass@host/db?sslmode=require

[github_oauth]
client_id = "..."
client_secret_env = "GITHUB_OAUTH_SECRET"

[security]
data_key_env = "RELAY_DATA_KEY"  # 32-byte base64; rotates cert keys, tokens at rest
```

Deploy artifacts:

- `docker-compose.yml` (relayd + postgres + optional caddy in front) — primary self-host path.
- Helm chart stub under `infra/helm/` — marked experimental.
- Systemd unit example for bare-metal.

## 12. Open-source posture

- License: **MIT**.
- Monorepo, workspace Cargo project.
- Contribution: CONTRIBUTING.md, CLA deferred.
- Public issue tracker; no proprietary closed-source hosted-only modules in v1.
- Hosted-specific bits (billing integration, later) will live in a separate `relay-hosted` repo private to Anthropic/andrea — core remains fully self-hostable.

## 13. Repo layout

```
relay-tunnels/
├── Cargo.toml                   # [workspace] members = ["crates/*", "crates/bins/*"]
├── rust-toolchain.toml
├── README.md
├── LICENSE                      # MIT
├── SPEC.md                      # this file
├── crates/
│   ├── relay-proto/             # wire protocol types (CBOR), version constants
│   ├── relay-db/                # sqlx layer, migrations runner, sqlite+postgres model
│   ├── relay-dns/               # DnsProvider trait + cloudflare/route53/rfc2136 impls
│   ├── relay-acme/              # ACME client wrapper, cert store, renewal worker
│   ├── relay-edge/              # QUIC ingress, HTTP/TCP public listeners, routing
│   ├── relay-control/           # axum API + Askama+HTMX dashboard
│   ├── relay-cli/               # `relay` CLI binary
│   └── relay-server/            # `relayd` binary (wires edge + control)
├── migrations/
│   ├── 20260417000001_init.sql
│   └── ...
├── infra/
│   ├── docker/
│   │   ├── Dockerfile
│   │   └── docker-compose.yml
│   ├── helm/                    # stub
│   └── systemd/relayd.service
└── docs/
    ├── architecture.md
    ├── self-hosting.md
    └── protocol.md
```

## 14. Milestones (suggested order)

1. **M0** — workspace scaffold, CI (fmt/clippy/test), `relay-proto` crate with CBOR types, basic integration test harness.
2. **M1** — QUIC data plane: `relay http <port>` against a local `relayd`, random hostname only, no auth, no TLS on the public side (HTTP only).
3. **M2** — control plane skeleton: GitHub OAuth, DB, API tokens, reservations CRUD in dashboard.
4. **M3** — TLS termination on edge for `*.sharedwithrelay.com` via Cloudflare DNS-01. Deployed to first box.
5. **M4** — TCP tunnels + port pool allocation.
6. **M5** — request inspection (capture + dashboard UI + live tail).
7. **M6** — custom domains (HTTP-01 ACME, TXT verification).
8. **M7** — self-host polish: docker-compose, docs, SQLite path validated.
9. **M8** — public MIT release at `github.com/…/relay`.

## 15. Open questions (to revisit before/during implementation)

- Port 443 UDP (QUIC) vs alt port for CLI: many corporate networks block outbound UDP. Fallback: CONNECT-proxy over TCP/443 (MASQUE later). Decision: **start UDP-only, accept corp-network limitation, add TCP fallback once there's demand**.
- Body capture size cap & retention default (proposed: 1 MiB / 7 days on hosted).
- Rate limits on reservations (squatting prevention). Proposed: max 5 active reservations per user on hosted, configurable on self-host.
