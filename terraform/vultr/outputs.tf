output "instance_ip" {
  value       = vultr_instance.nemesis.main_ip
  description = "Public IP address of the Vultr instance"
}

output "instance_id" {
  value       = vultr_instance.nemesis.id
  description = "Vultr instance ID"
}
