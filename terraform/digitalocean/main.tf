terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

provider "digitalocean" {
  token = var.digitalocean_token
}

# Upload SSH key
resource "digitalocean_ssh_key" "nemesis" {
  name       = "nemesis-${var.hostname}"
  public_key = var.ssh_public_key
}

# Create Droplet
resource "digitalocean_droplet" "nemesis" {
  image    = var.do_image
  name     = var.hostname
  region   = var.vps_region
  size     = var.vps_plan
  ssh_keys = [digitalocean_ssh_key.nemesis.fingerprint]

  tags = ["nemesis"]
}

# Generate Ansible inventory
resource "local_file" "ansible_inventory" {
  content = templatefile("${path.module}/inventory.tftpl", {
    hostname   = var.hostname
    ip_address = digitalocean_droplet.nemesis.ipv4_address
    username   = "root"
  })
  filename = "${path.module}/../../ansible/inventory/vps.yml"
}
