variable "vultr_api_key" {
  type      = string
  sensitive = true
}

variable "vps_region" {
  type    = string
  default = "ewr"
}

variable "vps_plan" {
  type    = string
  default = "vc2-1c-1gb"
}

variable "hostname" {
  type    = string
  default = "nemesis-vps"
}

variable "ssh_public_key" {
  type = string
}

variable "vultr_os_id" {
  type    = number
  default = 535 # Arch Linux
}
