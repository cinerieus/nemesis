packer {
  required_plugins {
    proxmox = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/proxmox"
    }
    ansible = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/ansible"
    }
  }
}

variable "proxmox_url" {
  type = string
}

variable "proxmox_token" {
  type      = string
  sensitive = true
}

variable "proxmox_node" {
  type = string
}

variable "proxmox_storage" {
  type    = string
  default = "local-lvm"
}

variable "proxmox_vm_id" {
  type    = number
  default = 9000
}

source "proxmox-iso" "archlinux" {
  proxmox_url              = var.proxmox_url
  token                    = var.proxmox_token
  node                     = var.proxmox_node
  insecure_skip_tls_verify = true

  iso_url          = var.iso_url
  iso_checksum     = var.iso_checksum
  iso_storage_pool = "local"
  unmount_iso      = true

  vm_id   = var.proxmox_vm_id
  vm_name = "nemesis-archlinux"

  template_name        = "nemesis-archlinux"
  template_description = "Nemesis Arch Linux template"

  cores  = var.vm_cpus
  memory = var.vm_memory

  scsi_controller = "virtio-scsi-single"

  disks {
    disk_size    = var.disk_size
    storage_pool = var.proxmox_storage
    type         = "scsi"
    format       = "raw"
  }

  network_adapters {
    model  = "virtio"
    bridge = "vmbr0"
  }

  efi_config {
    efi_storage_pool  = var.proxmox_storage
    efi_type          = "4m"
    pre_enrolled_keys = false
  }

  http_directory   = "http"
  ssh_username     = var.ssh_username
  ssh_password     = var.ssh_password
  ssh_port         = 22
  ssh_timeout      = "30m"
  boot_wait        = "5s"
  boot_command = [
    "<enter><wait60>",
    "echo '${var.ssh_password}' | passwd --stdin root<enter><wait2>",
    "systemctl start sshd<enter><wait2>",
    "curl -sL http://{{ .HTTPIP }}:{{ .HTTPPort }}/install.sh -o /tmp/install.sh<enter><wait2>",
    "chmod +x /tmp/install.sh<enter>",
    "LUKS_ENABLED=${var.luks_enabled} LUKS_PASSWORD='${var.luks_password}' /tmp/install.sh<enter>"
  ]

  qemu_agent = true
}

build {
  sources = ["source.proxmox-iso.archlinux"]

  provisioner "shell" {
    script = "scripts/bootstrap.sh"
  }

  provisioner "ansible-local" {
    playbook_file   = "../ansible/playbooks/vm.yml"
    playbook_dir    = "../ansible"
    extra_arguments = ["-e", "@../../nemesis.yml", "-e", "@../../secrets.yml"]
  }
}
