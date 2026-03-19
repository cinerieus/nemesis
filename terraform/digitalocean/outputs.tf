output "droplet_ip" {
  value       = digitalocean_droplet.nemesis.ipv4_address
  description = "Public IP address of the DigitalOcean droplet"
}

output "droplet_id" {
  value       = digitalocean_droplet.nemesis.id
  description = "DigitalOcean droplet ID"
}
