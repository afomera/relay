# Self-hosting relay

This guide walks through running `relayd` on a single host you control.

## Prerequisites

- One Linux host with public IPv4 (ports 80/TCP, 443/TCP, 443/UDP open).
- A domain you control (e.g. `tunnels.mycompany.com`). The host should already
  have DNS `A` (and `AAAA`) records pointing at it, plus a wildcard:

  ```
  tunnels.mycompany.com.           A    203.0.113.7
  *.tunnels.mycompany.com.         A    203.0.113.7
  *.temporary.tunnels.mycompany.com. A  203.0.113.7
  ```

- A DNS provider API token. v1 ships a working Cloudflare implementation;
  Route53 and RFC2136 are stubs (see `DECISIONS.md` and `crates/relay-dns/`).
- A GitHub OAuth App (for dashboard sign-in). Create one at
  `https://github.com/settings/developers`:
  - **Homepage URL**: `https://withrelay.mycompany.com` (or wherever the
    dashboard is reachable).
  - **Authorization callback URL**:
    `https://withrelay.mycompany.com/auth/github/callback`

## Generate the data key

`RELAY_DATA_KEY` encrypts cert private keys at rest and signs session cookies.
It must be at least 32 bytes of base64.

```sh
head -c 32 /dev/urandom | base64
```

**Keep this value safe.** Losing it means re-issuing every cert on boot.

## Configure

Copy `infra/docker/relayd.toml.example` to `relayd.toml` and edit the values.
Minimum fields to change:

- `server.public_url` — where the dashboard lives.
- `domains.base` — your tunnel domain (no scheme, no wildcard).
- `github_oauth.client_id` — your OAuth app's client id.
- `db.url` — SQLite path or Postgres URL.
- `dns.cloudflare.zone_id` — the Cloudflare zone id for `domains.base`.

Then set environment variables:

```sh
export RELAY_DATA_KEY="$(head -c 32 /dev/urandom | base64)"
export GITHUB_OAUTH_SECRET="your-github-app-secret"
export CLOUDFLARE_API_TOKEN="cf-token-with-zone-dns-edit"
```

## Run with docker-compose

```sh
cd infra/docker
docker compose up -d
```

`docker compose logs -f relayd` will show:

- ACME account creation + wildcard cert issuance (first boot takes ~30s).
- QUIC listener bound to `0.0.0.0:443/udp`.
- HTTPS ingress bound to `:443/tcp`.
- Control-plane listening on `127.0.0.1:7090`.

Put a reverse proxy (Caddy, Nginx) in front of `:7090` if the dashboard needs
to be reachable publicly — relayd deliberately binds it to loopback by default.

## Run with systemd

1. Build release: `cargo build --release --bin relayd`.
2. Copy: `sudo install target/release/relayd /usr/local/bin/relayd`.
3. Copy unit file: `sudo install infra/systemd/relayd.service /etc/systemd/system/`.
4. Create `/etc/relay/relayd.toml` (see example).
5. Create `/etc/relay/relayd.env` with the env vars above (mode 0600, owner `relay`).
6. `sudo systemctl enable --now relayd`.

## Verifying end-to-end

```sh
# Dashboard
curl -sS https://withrelay.mycompany.com/healthz
# → ok

# Sign in at /login with GitHub
# → /tokens → click "Create token" → copy the token it shows you

# On your dev machine:
relay auth login --token rly_pat_...
relay --server withrelay.mycompany.com:443 http 3000
# → https://<random>.temporary.tunnels.mycompany.com
```

## Backup & upgrade

- **SQLite**: `cp /var/lib/relay/relay.db backup-$(date +%F).db` (use
  `.backup` command inside `sqlite3` for consistency while running).
- **Postgres**: `pg_dump relay > backup.sql`.
- **Upgrading**: `docker compose pull && docker compose up -d` — migrations
  run automatically at boot.

Losing `RELAY_DATA_KEY` means:

- Sessions invalidate (users must sign in again).
- Stored cert private keys are unreadable — ACME re-issues on next renewal tick.

Re-issuance consumes Let's Encrypt rate-limits, so prefer rotating the key
only when necessary.

## What's implemented right now

See `SPEC.md` §14 for milestones. As of this build:

| Milestone | Status |
|-----------|--------|
| M1 HTTP tunnels over QUIC         | Implemented, integration-tested |
| M2 Dashboard, GitHub OAuth, DB    | Implemented |
| M3 TLS termination, cert store    | Implemented (HTTPS listener + resolver) |
| M3 ACME DNS-01 wildcard (Let's Encrypt) | Implemented |
| M3 DNS providers: Cloudflare      | Implemented |
| M3 DNS providers: Route53, RFC2136 | Stubbed |
| M4 TCP tunnels + port pool        | Implemented |
| M5 Request inspection             | Capture + DB schema scaffolded; UI viewer is TODO |
| M6 Custom domains                 | CRUD + UI present; DNS TXT verification is a stub |
| Postgres DB backend               | Stubbed — SQLite only for now |
