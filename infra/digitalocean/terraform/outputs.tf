output "reserved_ip" {
  description = "Public IP the DNS records point at."
  value       = digitalocean_reserved_ip.relay.ip_address
}

output "droplet_id" {
  value = digitalocean_droplet.relay.id
}

output "dashboard_url" {
  value = "https://${var.admin_hostname}"
}

output "ssh_command" {
  description = "Tail cloud-init logs to watch the first boot."
  value       = "ssh root@${digitalocean_reserved_ip.relay.ip_address} -- tail -f /var/log/cloud-init-output.log"
}

output "relay_data_key" {
  description = "Persist this somewhere safe - lose it and you lose every cert."
  value       = sensitive(local.data_key_b64)
  sensitive   = true
}
