# Deploying relay on DigitalOcean

Two paths:

- **Fast path — Terraform + cloud-init** (recommended). One `terraform
  apply` creates the Droplet, Reserved IP, Firewall, Cloudflare DNS
  records, and boots relay. ~3 minutes, zero manual ssh. See
  [`../infra/digitalocean/README.md`](../infra/digitalocean/README.md).

- **Manual path** (this doc). Step-by-step via the DO web UI + SSH.
  Useful if you want to understand every moving piece before handing
  control to Terraform, or you're bootstrapping without a CI pipeline.

First boot to first tunnel: ~20 minutes manual, ~3 minutes via Terraform.

## Why Cloudflare for DNS even on DO compute

`relay-acme` ships a Cloudflare DNS provider for wildcard certs via DNS-01.
Route53 and RFC2136 are stubbed, and there's no DigitalOcean DNS provider
yet. Cheapest working path: DO for compute, Cloudflare for DNS.

(If you want to keep everything at DO, adding a DigitalOcean DNS provider
is a ~100-line addition to `crates/relay-dns/` — ping me.)

## 1. Droplet + Reserved IP

```sh
# Using doctl; the web UI works identically.

# Regular droplet, 1 vCPU / 2 GB RAM / 50 GB SSD / 2 TB egress ≈ $12/mo.
# Pick a region near your users.
doctl compute droplet create relay-prod \
  --region nyc3 \
  --size s-1vcpu-2gb \
  --image ubuntu-24-04-x64 \
  --ssh-keys YOUR_SSH_KEY_ID \
  --wait

# Reserved IP (detachable from the droplet — keeps DNS stable across resizes).
doctl compute reserved-ip create --region nyc3
doctl compute reserved-ip-action assign <RESERVED_IP> <DROPLET_ID>
```

The Reserved IP is the address your DNS records will point at.

## 2. Cloud Firewall

In DO Networking → Firewalls → Create. Attach to `relay-prod`.

| Rule | Protocol | Ports | Sources |
|---|---|---|---|
| SSH | TCP | 22 | your laptop only |
| HTTP | TCP | 80 | 0.0.0.0/0, ::/0 |
| HTTPS (and QUIC) | TCP | 443 | 0.0.0.0/0, ::/0 |
| QUIC | UDP | 443 | 0.0.0.0/0, ::/0 |
| TCP tunnel pool | TCP | 29000-29999 | 0.0.0.0/0, ::/0 |

Outbound: allow all (ACME and CLI upstream need to reach out).

## 3. Cloudflare DNS

At Cloudflare, add zone `sharedwithrelay.com`. Update the domain's
nameservers at your registrar (or wherever `sharedwithrelay.com` is
registered — not DO's DNS, or DNS-01 won't work).

Records (replace `RESERVED_IP` with yours):

```
sharedwithrelay.com.              A   RESERVED_IP
*.sharedwithrelay.com.            A   RESERVED_IP
*.temporary.sharedwithrelay.com.  A   RESERVED_IP

# For the dashboard at dash.withrelay.dev, in the withrelay.dev zone:
dash.withrelay.dev.               A   RESERVED_IP
```

Optionally `AAAA` the same set if you enable IPv6 on the droplet.

**Proxy status: DNS only (grey cloud)**. Cloudflare's orange-cloud proxy
terminates TLS + strips QUIC and will break tunnels. Keep it grey on all
three records.

Create a Cloudflare API token at
`https://dash.cloudflare.com/profile/api-tokens` with the `Edit zone DNS`
template, scoped to `sharedwithrelay.com`. Save the token.

Copy the **zone id** from the zone's overview page (right sidebar).

## 4. Server prep

SSH in as root, create a non-root user, install Docker:

```sh
ssh root@RESERVED_IP

adduser --disabled-password --gecos '' relay
usermod -aG sudo relay
rsync --archive --chown=relay:relay ~/.ssh /home/relay/

# Docker + compose plugin
curl -fsSL https://get.docker.com | sh
usermod -aG docker relay

# Swap file (1 GB droplets benefit; harmless on 2 GB).
fallocate -l 2G /swapfile && chmod 600 /swapfile \
  && mkswap /swapfile && swapon /swapfile \
  && echo '/swapfile none swap sw 0 0' >> /etc/fstab

# Unprivileged users need CAP_NET_BIND_SERVICE to bind :80/:443 — Docker
# already handles this, so nothing extra.
exit
```

## 5. Deploy relay

Back on your laptop, from the relay repo:

```sh
# Copy the source. The repo's Dockerfile does a multi-stage build.
rsync -az --exclude target --exclude relay-dev.db . relay@RESERVED_IP:/home/relay/relay/

ssh relay@RESERVED_IP
cd /home/relay/relay/infra/docker
cp relayd.toml.example relayd.toml
vim relayd.toml   # edit as below
```

Minimum changes to `relayd.toml`:

```toml
[server]
bind_http      = "0.0.0.0:80"
bind_https     = "0.0.0.0:443"
bind_quic      = "0.0.0.0:443"
bind_admin     = "127.0.0.1:7090"           # loopback fallback
admin_hostname = "dash.withrelay.dev"       # edge serves the dashboard here
public_url     = "https://dash.withrelay.dev"
tunnel_scheme  = "https"

[domains]
base      = "sharedwithrelay.com"
temporary = "temporary.sharedwithrelay.com"

[db]
url = "sqlite:///var/lib/relay/relay.db"

[github_oauth]
client_id         = "Iv1.abcdef..."
client_secret_env = "GITHUB_OAUTH_SECRET"

[security]
data_key_env = "RELAY_DATA_KEY"

[dns]
provider = "cloudflare"

[dns.cloudflare]
api_token_env = "CLOUDFLARE_API_TOKEN"
zone_id       = "YOUR_CLOUDFLARE_ZONE_ID"

[acme]
# Staging first! Flip to prod once a staging cert issues cleanly.
directory     = "https://acme-staging-v02.api.letsencrypt.org/directory"
contact_email = "you@example.com"
```

Create `.env` in the same directory (never commit this):

```sh
RELAY_DATA_KEY=$(head -c 32 /dev/urandom | base64)
GITHUB_OAUTH_SECRET=your-github-oauth-app-secret
CLOUDFLARE_API_TOKEN=cf-token-with-zone-dns-edit
POSTGRES_PASSWORD=unused-until-postgres-lands
```

Load it:

```sh
set -a; source .env; set +a
docker compose up -d --build
docker compose logs -f relayd
```

On first boot you'll see:

```
[acme] staging ... creating ACME account
[acme] publishing ACME challenge  record=_acme-challenge.sharedwithrelay.com
[acme] wildcard cert installed    hostname=*.sharedwithrelay.com
```

Takes ~30 seconds. If it fails, the log line tells you why (most common:
Cloudflare token missing the zone, or zone id mismatch).

Once staging succeeds, flip `[acme] directory` to
`https://acme-v02.api.letsencrypt.org/directory` and restart the
container. Production cert issues on next boot.

## 6. Dashboard access

With `[server] admin_hostname = "dash.withrelay.dev"` set, the edge serves
the dashboard on :80/:443 for that host, co-existing with tunnel traffic
on the same ports — no reverse proxy, no second TLS stack. The cert for
`dash.withrelay.dev` is issued via ACME HTTP-01 on boot (same flow as
custom domains).

Watch the logs on first boot:

```
[acme] issuing HTTP-01 cert  hostname=dash.withrelay.dev
[acme] HTTP-01 cert installed hostname=dash.withrelay.dev
```

Then visit `https://dash.withrelay.dev` — green lock, GitHub sign-in.

GitHub OAuth app:
- **Homepage URL**: `https://dash.withrelay.dev`
- **Callback URL**: `https://dash.withrelay.dev/auth/github/callback`

`bind_admin = 127.0.0.1:7090` stays as a loopback fallback — useful for
health checks (`curl http://127.0.0.1:7090/healthz`) or emergency SSH
tunnel access if DNS/ACME are broken.

## 7. Smoke test from your laptop

```sh
# Sign in at the dashboard, create a token.
relay auth login --token rly_pat_...

# Open a tunnel
relay --server sharedwithrelay.com:443 http 3000
# → https://bright-otter-a9f2.temporary.sharedwithrelay.com
```

The first request on any hostname warms up the HTTPS resolver. If you
hit a custom domain before its HTTP-01 cert has issued, the CLI's
browser warning won't matter yet — verify via the dashboard first, wait
for `cert installed` in logs, then hit it.

## 8. Ops

- **Logs**: `docker compose logs -f relayd`
- **Restart**: `docker compose restart relayd`
- **Upgrade**: `git pull && docker compose up -d --build`
- **Backup**: `cp /var/lib/docker/volumes/docker_relay-data/_data/relay.db backup-$(date +%F).db`
- **Delete stuck tunnels**: the dashboard's `clear disconnected` button
  handles everything the restart-sweep missed.

## Things to wire up before you publicize the URL

- GitHub OAuth app with the prod callback
- Dashboard on a real hostname (not just the SSH tunnel) with its own TLS
- Monitoring — even just a uptime check on `https://sharedwithrelay.com/healthz`
- Log shipping (optional — `relayd` emits structured tracing via `RUST_LOG`)
- Postgres backend (SQLite is fine until ~100s of concurrent tunnels,
  then you'll want it for durability and multi-writer safety)
