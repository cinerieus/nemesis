SHELL := /bin/bash
.DEFAULT_GOAL := help

# Configuration
CONFIG := nemesis.yml
SECRETS := secrets.yml
ANSIBLE_DIR := ansible
VAULT_ARGS := --vault-password-file .vault-pass

# Check if vault password file exists, otherwise prompt
ifneq ($(wildcard .vault-pass),)
    VAULT_CMD := $(VAULT_ARGS)
else
    VAULT_CMD := --ask-vault-pass
endif

# Common Ansible args
ANSIBLE_COMMON := -e @$(CONFIG) -e @$(SECRETS) $(VAULT_CMD)

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# === VM Builds ===

.PHONY: vm-kvm
vm-kvm: ## Create + configure VM on remote KVM host (set libvirt_uri in nemesis.yml)
	@LIBVIRT_URI=$$(python3 -c "import yaml; print(yaml.safe_load(open('$(CONFIG)'))['libvirt_uri'])" 2>/dev/null); \
	SSH_KEY=$$(head -1 config/ssh/authorized_keys | grep -v '^#' || echo ""); \
	if [ -z "$$LIBVIRT_URI" ]; then echo "Error: Set libvirt_uri in nemesis.yml (e.g. qemu+ssh://user@host/system)"; exit 1; fi; \
	if [ -z "$$SSH_KEY" ]; then echo "Error: Add an SSH key to config/ssh/authorized_keys"; exit 1; fi; \
	cd terraform/libvirt && terraform init && terraform apply -auto-approve \
		-var="libvirt_uri=$$LIBVIRT_URI" \
		-var="ssh_public_key=$$SSH_KEY" \
		-var="hostname=$$(python3 -c "import yaml; c=yaml.safe_load(open('../../$(CONFIG)')); print(c.get('hostname') or 'nemesis-vm')")" \
		-var="vm_memory=$$(python3 -c "import yaml; print(yaml.safe_load(open('../../$(CONFIG)')).get('vm_memory', 4096))")" \
		-var="vm_cpus=$$(python3 -c "import yaml; print(yaml.safe_load(open('../../$(CONFIG)')).get('vm_cpus', 2))")" \
		-var="storage_pool=$$(python3 -c "import yaml; print(yaml.safe_load(open('../../$(CONFIG)')).get('libvirt_storage_pool', 'default'))")" \
		-var="network_name=$$(python3 -c "import yaml; print(yaml.safe_load(open('../../$(CONFIG)')).get('libvirt_network', 'default'))")"
	cd $(ANSIBLE_DIR) && ansible-playbook -i inventory/vm.yml playbooks/vm.yml $(ANSIBLE_COMMON)

.PHONY: vm-proxmox
vm-proxmox: ## Build Proxmox VM template with Packer
	cd packer && packer init . && packer build archlinux-proxmox.pkr.hcl

# === VPS Provisioning ===

.PHONY: vps-vultr
vps-vultr: ## Provision Vultr VPS (Terraform + Ansible)
	cd terraform/vultr && terraform init && terraform apply -auto-approve
	cd terraform/scripts && bash generate-inventory.sh vultr
	cd $(ANSIBLE_DIR) && ansible-playbook -i inventory/vps.yml playbooks/vps.yml $(ANSIBLE_COMMON)

.PHONY: vps-do
vps-do: ## Provision DigitalOcean VPS (Terraform + Ansible)
	cd terraform/digitalocean && terraform init && terraform apply -auto-approve
	cd terraform/scripts && bash generate-inventory.sh digitalocean
	cd $(ANSIBLE_DIR) && ansible-playbook -i inventory/vps.yml playbooks/vps.yml $(ANSIBLE_COMMON)

# === Configure existing hosts ===

.PHONY: configure
configure: ## Configure a host via SSH (HOST=ip PLAY=vm|vps)
	@if [ -z "$(HOST)" ]; then echo "Usage: make configure HOST=10.0.0.5 PLAY=vps"; exit 1; fi
	@PLAY=$${PLAY:-vps}; \
	echo "[nemesis]" > /tmp/nemesis-inventory.ini; \
	echo "$(HOST) ansible_user=root" >> /tmp/nemesis-inventory.ini; \
	cd $(ANSIBLE_DIR) && ansible-playbook \
		-i /tmp/nemesis-inventory.ini \
		playbooks/$${PLAY}.yml \
		$(ANSIBLE_COMMON)

# === Ansible Direct ===

.PHONY: playbook-vm
playbook-vm: ## Run VM playbook against inventory
	cd $(ANSIBLE_DIR) && ansible-playbook playbooks/vm.yml $(ANSIBLE_COMMON)

.PHONY: playbook-vps
playbook-vps: ## Run VPS playbook against inventory
	cd $(ANSIBLE_DIR) && ansible-playbook playbooks/vps.yml $(ANSIBLE_COMMON)

# === Vault ===

.PHONY: vault-encrypt
vault-encrypt: ## Encrypt secrets.yml with Ansible Vault
	ansible-vault encrypt $(SECRETS)

.PHONY: vault-decrypt
vault-decrypt: ## Decrypt secrets.yml for editing
	ansible-vault decrypt $(SECRETS)

.PHONY: vault-edit
vault-edit: ## Edit encrypted secrets.yml
	ansible-vault edit $(SECRETS)

# === Validation ===

.PHONY: lint
lint: ## Run ansible-lint on playbooks
	cd $(ANSIBLE_DIR) && ansible-lint playbooks/

.PHONY: check-vm
check-vm: ## Dry run VM playbook
	cd $(ANSIBLE_DIR) && ansible-playbook --check playbooks/vm.yml $(ANSIBLE_COMMON)

.PHONY: check-vps
check-vps: ## Dry run VPS playbook
	cd $(ANSIBLE_DIR) && ansible-playbook --check playbooks/vps.yml $(ANSIBLE_COMMON)

.PHONY: validate-packer
validate-packer: ## Validate Packer templates
	cd packer && packer validate archlinux-proxmox.pkr.hcl

.PHONY: validate-terraform
validate-terraform: ## Validate Terraform modules
	cd terraform/libvirt && terraform init -backend=false && terraform validate
	cd terraform/vultr && terraform init -backend=false && terraform validate
	cd terraform/digitalocean && terraform init -backend=false && terraform validate

# === Cleanup ===

.PHONY: clean
clean: ## Remove build artifacts
	rm -f /tmp/nemesis-inventory.ini

.PHONY: destroy-vm
destroy-vm: ## Destroy KVM VM on remote host
	cd terraform/libvirt && terraform destroy

.PHONY: destroy-vultr
destroy-vultr: ## Destroy Vultr VPS
	cd terraform/vultr && terraform destroy

.PHONY: destroy-do
destroy-do: ## Destroy DigitalOcean VPS
	cd terraform/digitalocean && terraform destroy
