# DigitalOcean Terraform deploy

One-shot deployment: Droplet, Reserved IP, Firewall, Cloudflare DNS records,
and a cloud-init that installs Docker + relay and boots it. First
`terraform apply` to live `https://dash.withrelay.dev` in ~3 minutes.

## Pre-deploy checklist

Work top-to-bottom. Each step depends on the ones above it.

### 1. Tools locally
- [ ] `terraform` ≥ 1.6
- [ ] (optional) `doctl` for poking around after deploy

### 2. Domains at Cloudflare
- [ ] Tunnel domain (e.g. `sharedwithrelay.com`) has Cloudflare nameservers
      at the registrar. Verify: `dig NS sharedwithrelay.com` returns
      `*.ns.cloudflare.com`.
- [ ] Dashboard parent domain (e.g. `withrelay.dev`) same.
      (OK if these are the same zone.)
- [ ] Copy both **zone ids** from each zone's overview page sidebar.

### 3. DigitalOcean
- [ ] An SSH public key uploaded — Settings → Security → SSH keys.
      Note its numeric id: `doctl compute ssh-key list`.
- [ ] **API token** with write scope — API → Tokens → Generate New Token.

### 4. Cloudflare
- [ ] **API token** at
      `https://dash.cloudflare.com/profile/api-tokens` using the
      `Edit zone DNS` template, scoped to both zones from step 2.

### 5. GitHub OAuth App
Decide the admin hostname first (e.g. `dash.withrelay.dev`), then:

- [ ] Create the OAuth App at
      `https://github.com/settings/developers` → New OAuth App.
  - **Homepage URL**: `https://dash.withrelay.dev`
  - **Authorization callback URL**: `https://dash.withrelay.dev/auth/github/callback`
- [ ] Copy the **Client ID**.
- [ ] Generate a **Client secret** and copy immediately — GitHub only
      shows it once.
- [ ] Decide whether to restrict sign-in to members of a GitHub org. If
      yes, note the org slug (e.g. `mycompany`) for
      `github_allowed_orgs`. `read:org` scope is added automatically
      when the list is non-empty.

### 6. relay repo published
The cloud-init `git clone`s the source. That repo has to exist publicly
(or privately, with a deploy-key-auth workaround you'd set up yourself).

- [ ] Push this codebase to a GitHub repo you control.
- [ ] Put the clone URL in `relay_git_url` (defaults may not match).

### 7. (Only if you care) ACME staging first
The Terraform defaults to Let's Encrypt **staging** because it has
generous rate limits. Staging certs aren't browser-trusted, but if your
first deploy hits a configuration mistake, staging won't cost you a
prod rate-limit strike.

Flip `acme_directory` to `https://acme-v02.api.letsencrypt.org/directory`
in `terraform.tfvars` once staging issues cleanly, then re-apply.

---

After the checklist is green, copy `terraform.tfvars.example` →
`terraform.tfvars`, fill in, and continue below.

## Usage

```sh
cd infra/digitalocean/terraform
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars             # fill in all the non-defaults

terraform init
terraform apply
```

Terraform creates everything, waits for cloud-init, and prints the Reserved
IP + dashboard URL. First boot the droplet runs ACME **staging** by default
(see `acme_directory` in vars) — safer while DNS is settling. Flip to prod
in `terraform.tfvars` and `terraform apply` again (triggers a fresh first
boot; state resets).

## What the cloud-init does

1. apt-updates, installs git + docker + docker-compose-v2
2. Creates a `relay` user, copies SSH keys from root
3. Adds a 2 GB swapfile (helps 1–2 GB droplets)
4. Clones `relay_git_url@relay_git_ref` into `/home/relay/relay`
5. Renders `relayd.toml` and `.env` from your Terraform variables
6. `docker compose up -d --build` in `infra/docker/`

Watch it live once the droplet is up:

```sh
ssh relay@$(terraform output -raw reserved_ip) -- 'docker compose -f /home/relay/relay/infra/docker/docker-compose.yml logs -f'
```

## Secrets

`terraform.tfvars` should **never** be committed. `.gitignore` is set up
accordingly. The only thing that ends up in Terraform state is the
encrypted form (state file itself contains secrets — store it in a
private remote backend like Terraform Cloud or an encrypted S3 bucket
before you scale past one operator).

## Updates

**Split of concerns:**

- **Terraform** owns the infra lifecycle — droplet size, firewall rules,
  Reserved IP, DNS records. `terraform apply` after a var change updates
  these in place.
- **Cloud-init runs exactly once** (first boot). Changing `relay_git_ref`
  in `terraform.tfvars` and re-applying does *not* redeploy relay.
- **`update.sh`** handles app updates. It pulls git, rebuilds the image,
  restarts the container. DB migrations run automatically at startup;
  certs survive restarts.

**From your laptop:**

```sh
# Update to latest main
./remote-update.sh

# Pin to a tag/branch
./remote-update.sh v0.2.0

# Override target host (if terraform state isn't handy)
DROPLET_HOST=relay@1.2.3.4 ./remote-update.sh
```

Takes ~30 seconds total; container downtime is ~3 seconds during restart.
Active CLI tunnels drop, then reconnect automatically via the built-in
exponential backoff — users see one blip, URLs stay stable.

**Infra changes that require Terraform:**

- Resizing the droplet — `terraform apply` after changing `droplet_size`.
  Note: DO can resize in place without destruction if you use the disk=false
  flag; the default via Terraform forces recreation, which loses the SQLite
  DB (back up first, or switch to managed Postgres).
- Firewall rules, SSH source CIDRs — `terraform apply`.
- Adding DNS records — `terraform apply` (or edit by hand in Cloudflare;
  Terraform will try to reconcile next apply).

**Things that just work:**

- Certificate renewals — `RenewalWorker` ticks hourly and re-issues anything
  within 30 days of expiry.
- DB migrations — run in-process at startup, before the edge listeners bind.
- OS security updates — not automatic. `sudo apt update && sudo unattended-upgrade`
  or enable the unattended-upgrades package if you want hands-off kernel patches.

## Destroy

```sh
terraform destroy
```

Drops the droplet, reserved IP, firewall, and DNS records. Your SQLite DB
goes with the droplet — grab a backup via
`scp relay@$(terraform output -raw reserved_ip):/var/lib/docker/volumes/docker_relay-data/_data/relay.db ./relay-backup-$(date +%F).db`
first if you care about the data.
