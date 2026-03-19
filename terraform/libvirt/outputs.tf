output "vm_ip" {
  value       = libvirt_domain.vm.network_interface[0].addresses[0]
  description = "IP address of the VM"
}

output "vm_name" {
  value       = libvirt_domain.vm.name
  description = "Libvirt domain name"
}
