// Auto-generate a data key if the user didn't supply one.
resource "random_bytes" "data_key" {
  length = 32
}

locals {
  data_key_b64 = var.relay_data_key != "" ? var.relay_data_key : random_bytes.data_key.base64

  // The Cloudflare provider accepts full record names even when they nest
  // below the zone. `cf_record_name` turns the admin hostname into the
  // record name relative to its zone. (We don't actually need to — CF
  // accepts `dash.withrelay.dev` when zone_id is withrelay.dev's — but
  // passing short names keeps plans diff-clean.)
  cf_admin_record = var.admin_hostname
}

// ---- Infra -----------------------------------------------------------------

resource "digitalocean_reserved_ip" "relay" {
  region = var.region
}

resource "digitalocean_droplet" "relay" {
  name     = var.droplet_name
  image    = "ubuntu-24-04-x64"
  region   = var.region
  size     = var.droplet_size
  ssh_keys = var.ssh_key_ids
  ipv6     = true

  user_data = templatefile("${path.module}/../cloud-init.yaml.tftpl", {
    data_key_b64               = local.data_key_b64
    github_oauth_client_id     = var.github_oauth_client_id
    github_oauth_client_secret = var.github_oauth_client_secret
    github_allowed_orgs_toml   = jsonencode(var.github_allowed_orgs) // TOML accepts JSON-style arrays
    cloudflare_api_token       = var.cloudflare_api_token
    acme_contact_email         = var.acme_contact_email
    acme_directory             = var.acme_directory
    tunnel_base_domain         = var.tunnel_base_domain
    tunnel_zone_id             = var.tunnel_zone_id
    admin_hostname             = var.admin_hostname
    relay_git_url              = var.relay_git_url
    relay_git_ref              = var.relay_git_ref
  })
}

resource "digitalocean_reserved_ip_assignment" "relay" {
  ip_address = digitalocean_reserved_ip.relay.ip_address
  droplet_id = digitalocean_droplet.relay.id
}

resource "digitalocean_firewall" "relay" {
  name        = var.droplet_name
  droplet_ids = [digitalocean_droplet.relay.id]

  // SSH — tighten ssh_allow_from to your office IP(s) in prod.
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.ssh_allow_from
  }

  // Public HTTP + HTTPS + QUIC (UDP).
  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  inbound_rule {
    protocol         = "udp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  // TCP tunnel port pool. Shrink to a smaller range if you won't use TCP tunnels.
  inbound_rule {
    protocol         = "tcp"
    port_range       = "29000-29999"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  // Unrestricted egress — ACME, GitHub OAuth, Cloudflare API all need out.
  outbound_rule {
    protocol              = "tcp"
    port_range            = "all"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "udp"
    port_range            = "all"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

// ---- DNS (Cloudflare) ------------------------------------------------------

// Tunnel domain apex + wildcards. All DNS-only (proxied=false) because
// Cloudflare's orange-cloud proxy terminates TLS and breaks QUIC.

resource "cloudflare_record" "tunnel_apex" {
  zone_id = var.tunnel_zone_id
  name    = var.tunnel_base_domain
  content = digitalocean_reserved_ip.relay.ip_address
  type    = "A"
  proxied = false
  ttl     = 300
}

resource "cloudflare_record" "tunnel_wildcard" {
  zone_id = var.tunnel_zone_id
  name    = "*.${var.tunnel_base_domain}"
  content = digitalocean_reserved_ip.relay.ip_address
  type    = "A"
  proxied = false
  ttl     = 300
}

resource "cloudflare_record" "tunnel_temp_wildcard" {
  zone_id = var.tunnel_zone_id
  name    = "*.temporary.${var.tunnel_base_domain}"
  content = digitalocean_reserved_ip.relay.ip_address
  type    = "A"
  proxied = false
  ttl     = 300
}

resource "cloudflare_record" "dashboard" {
  zone_id = var.admin_zone_id
  name    = local.cf_admin_record
  content = digitalocean_reserved_ip.relay.ip_address
  type    = "A"
  proxied = false
  ttl     = 300
}
