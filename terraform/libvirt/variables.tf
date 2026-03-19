variable "libvirt_uri" {
  type        = string
  description = "Libvirt connection URI (e.g. qemu+ssh://user@host/system)"
}

variable "hostname" {
  type    = string
  default = "nemesis-vm"
}

variable "vm_memory" {
  type    = number
  default = 4096
}

variable "vm_cpus" {
  type    = number
  default = 2
}

variable "disk_size_bytes" {
  type        = number
  default     = 53687091200 # 50GB in bytes
  description = "Disk size in bytes (50GB = 53687091200)"
}

variable "storage_pool" {
  type    = string
  default = "default"
}

variable "network_name" {
  type    = string
  default = "default"
}

variable "use_dhcp" {
  type    = bool
  default = true
}

variable "arch_cloud_image_url" {
  type    = string
  default = "https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2"
}

variable "ssh_public_key" {
  type = string
}

variable "root_password" {
  type      = string
  sensitive = true
  default   = "changeme"
}
