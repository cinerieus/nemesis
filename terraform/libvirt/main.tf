terraform {
  required_providers {
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "~> 0.8"
    }
  }
}

provider "libvirt" {
  uri = var.libvirt_uri
}

# Download Arch Linux cloud image
resource "libvirt_volume" "arch_base" {
  name   = "arch-cloudimg-base.qcow2"
  pool   = var.storage_pool
  source = var.arch_cloud_image_url
  format = "qcow2"
}

# Create VM disk from base image
resource "libvirt_volume" "vm_disk" {
  name           = "${var.hostname}-disk.qcow2"
  pool           = var.storage_pool
  base_volume_id = libvirt_volume.arch_base.id
  size           = var.disk_size_bytes
  format         = "qcow2"
}

# Cloud-init: set root password, enable SSH, add keys
resource "libvirt_cloudinit_disk" "init" {
  name = "${var.hostname}-cloudinit.iso"
  pool = var.storage_pool

  user_data = templatefile("${path.module}/cloud-init.cfg.tftpl", {
    hostname       = var.hostname
    ssh_public_key = var.ssh_public_key
    root_password  = var.root_password
  })

  network_config = templatefile("${path.module}/network-config.cfg.tftpl", {
    use_dhcp = var.use_dhcp
  })
}

# Create the VM
resource "libvirt_domain" "vm" {
  name   = var.hostname
  memory = var.vm_memory
  vcpu   = var.vm_cpus

  cloudinit = libvirt_cloudinit_disk.init.id

  cpu {
    mode = "host-passthrough"
  }

  disk {
    volume_id = libvirt_volume.vm_disk.id
    scsi      = true
  }

  network_interface {
    network_name   = var.network_name
    wait_for_lease = true
  }

  console {
    type        = "pty"
    target_port = "0"
    target_type = "serial"
  }

  graphics {
    type        = "vnc"
    listen_type = "address"
  }

  # UEFI firmware
  firmware = "/usr/share/OVMF/OVMF_CODE.fd"
  nvram {
    file     = "/var/lib/libvirt/qemu/nvram/${var.hostname}_VARS.fd"
    template = "/usr/share/OVMF/OVMF_VARS.fd"
  }
}

# Wait for VM to get an IP
resource "null_resource" "wait_for_ssh" {
  depends_on = [libvirt_domain.vm]

  provisioner "remote-exec" {
    inline = ["echo 'SSH is up'"]

    connection {
      type     = "ssh"
      host     = libvirt_domain.vm.network_interface[0].addresses[0]
      user     = "root"
      password = var.root_password
      timeout  = "5m"
    }
  }
}

# Generate Ansible inventory
resource "local_file" "ansible_inventory" {
  depends_on = [null_resource.wait_for_ssh]

  content = templatefile("${path.module}/inventory.tftpl", {
    hostname   = var.hostname
    ip_address = libvirt_domain.vm.network_interface[0].addresses[0]
  })
  filename = "${path.module}/../../ansible/inventory/vm.yml"
}
