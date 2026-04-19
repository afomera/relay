// ---- Provider tokens -------------------------------------------------------

variable "do_token" {
  description = "DigitalOcean API token with write scope."
  type        = string
  sensitive   = true
}

variable "cloudflare_api_token" {
  description = "Cloudflare token with Zone:DNS:Edit on tunnel + admin zones."
  type        = string
  sensitive   = true
}

// ---- Droplet ---------------------------------------------------------------

variable "region" {
  description = "DigitalOcean region slug (nyc3, sfo3, ams3, ...)."
  type        = string
  default     = "nyc3"
}

variable "droplet_size" {
  description = "DO size slug. s-1vcpu-2gb (~$12/mo) is fine for launch."
  type        = string
  default     = "s-1vcpu-2gb"
}

variable "droplet_name" {
  type    = string
  default = "relay-prod"
}

variable "ssh_key_ids" {
  description = "DO SSH key ids (`doctl compute ssh-key list`)."
  type        = list(number)
}

variable "ssh_allow_from" {
  description = "CIDRs allowed to SSH in. Default: anywhere. Tighten to your office IPs for real deploys."
  type        = list(string)
  default     = ["0.0.0.0/0", "::/0"]
}

// ---- Domains ---------------------------------------------------------------

variable "tunnel_base_domain" {
  description = "Base tunnel domain, e.g. sharedwithrelay.com."
  type        = string
}

variable "marketing_url" {
  description = "Optional marketing site shown when visitors land on the apex of tunnel_base_domain with no subdomain. Leave empty to fall back to the generic 404."
  type        = string
  default     = ""
}

variable "tunnel_zone_id" {
  description = "Cloudflare zone id for tunnel_base_domain."
  type        = string
}

variable "admin_hostname" {
  description = "Dashboard hostname, e.g. dash.withrelay.dev."
  type        = string
}

variable "admin_zone_id" {
  description = "Cloudflare zone id that contains admin_hostname."
  type        = string
}

// ---- relay config ----------------------------------------------------------

variable "github_oauth_client_id" {
  description = "GitHub OAuth App client id."
  type        = string
}

variable "github_oauth_client_secret" {
  description = "GitHub OAuth App client secret."
  type        = string
  sensitive   = true
}

variable "github_allowed_orgs" {
  description = "When non-empty, sign-in is restricted to members of these GitHub orgs."
  type        = list(string)
  default     = []
}

variable "acme_contact_email" {
  description = "Email that ACME uses for account + expiry notices."
  type        = string
}

// ---- Database --------------------------------------------------------------
//
// Leave `database_url` empty to use on-disk SQLite at /var/lib/relay/relay.db
// (the single-host default). Set it to a managed Postgres connection string
// (PlanetScale Postgres, Neon, Crunchy, Fly) to point relay at Postgres
// instead. The URL is injected as `DATABASE_URL`; relayd picks it up via
// `db.url_env = "DATABASE_URL"` in the generated config.

variable "database_url" {
  description = "Managed Postgres URL (e.g. postgres://user:pass@host/db?sslmode=require). Leave empty for SQLite."
  type        = string
  default     = ""
  sensitive   = true
}

variable "db_max_connections" {
  description = "Optional pool-size override. Unset falls back to relay-db defaults (SQLite=10, Postgres=20)."
  type        = number
  default     = null
}

variable "db_acquire_timeout_secs" {
  description = "Optional per-acquire timeout in seconds. Unset falls back to the 5s default."
  type        = number
  default     = null
}

variable "acme_directory" {
  description = "ACME directory URL. Start on staging; flip to prod once verified."
  type        = string
  default     = "https://acme-staging-v02.api.letsencrypt.org/directory"
}

variable "acme_delegation_zone" {
  description = "Subdomain Relay uses for ACME DNS-01 delegation when issuing certs for customers' wildcard custom domains. Customers CNAME `_acme-challenge.<their-domain>` to `<slug>.<this-zone>` once, and renewals run unattended. Must live under the same Cloudflare zone as tunnel_zone_id — the DNS provider is single-zone today. Example: \"acme-delegate.sharedwithrelay.com\". Leave empty to disable wildcard custom domains."
  type        = string
  default     = ""
}

variable "relay_data_key" {
  description = "32-byte base64 data key. Leave empty to auto-generate."
  type        = string
  default     = ""
  sensitive   = true
}

variable "relay_git_url" {
  description = "Public clone URL of the relay repo."
  type        = string
  default     = "https://github.com/afomera/relay.git"
}

variable "relay_git_ref" {
  description = "Git branch/tag to deploy from."
  type        = string
  default     = "main"
}
