variable "digitalocean_token" {
  type      = string
  sensitive = true
}

variable "vps_region" {
  type    = string
  default = "nyc1"
}

variable "vps_plan" {
  type    = string
  default = "s-1vcpu-1gb"
}

variable "hostname" {
  type    = string
  default = "nemesis-vps"
}

variable "ssh_public_key" {
  type = string
}

variable "do_image" {
  type    = string
  default = "arch-linux-20231001" # Custom Arch image or marketplace slug
}
