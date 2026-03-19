terraform {
  required_providers {
    vultr = {
      source  = "vultr/vultr"
      version = "~> 2.0"
    }
  }
}

provider "vultr" {
  api_key = var.vultr_api_key
}

# Upload SSH key
resource "vultr_ssh_key" "nemesis" {
  name    = "nemesis-${var.hostname}"
  ssh_key = var.ssh_public_key
}

# Create Arch Linux instance
resource "vultr_instance" "nemesis" {
  plan        = var.vps_plan
  region      = var.vps_region
  os_id       = var.vultr_os_id # Arch Linux OS ID
  label       = var.hostname
  hostname    = var.hostname
  ssh_key_ids = [vultr_ssh_key.nemesis.id]

  tags = ["nemesis"]
}

# Generate Ansible inventory
resource "local_file" "ansible_inventory" {
  content = templatefile("${path.module}/inventory.tftpl", {
    hostname   = var.hostname
    ip_address = vultr_instance.nemesis.main_ip
    username   = "root"
  })
  filename = "${path.module}/../../ansible/inventory/vps.yml"
}
