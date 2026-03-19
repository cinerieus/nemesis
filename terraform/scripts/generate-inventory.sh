#!/bin/bash
# Generate Ansible inventory from Terraform output
# Usage: ./generate-inventory.sh <provider>
# Provider: vultr, digitalocean
set -euo pipefail

PROVIDER="${1:-vultr}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="${SCRIPT_DIR}/../${PROVIDER}"
INVENTORY_DIR="${SCRIPT_DIR}/../../ansible/inventory"

if [ ! -d "${TF_DIR}" ]; then
    echo "Error: Terraform directory not found: ${TF_DIR}"
    exit 1
fi

cd "${TF_DIR}"

# Get IP from Terraform output
case "${PROVIDER}" in
    vultr)
        IP=$(terraform output -raw instance_ip)
        ;;
    digitalocean)
        IP=$(terraform output -raw droplet_ip)
        ;;
    *)
        echo "Error: Unknown provider: ${PROVIDER}"
        exit 1
        ;;
esac

if [ -z "${IP}" ]; then
    echo "Error: Could not get IP address from Terraform output"
    exit 1
fi

# Write inventory
cat > "${INVENTORY_DIR}/vps.yml" <<EOF
all:
  children:
    vps:
      hosts:
        nemesis-vps:
          ansible_host: ${IP}
          ansible_user: root
          ansible_ssh_common_args: '-o StrictHostKeyChecking=no'
EOF

echo "Inventory written to ${INVENTORY_DIR}/vps.yml (IP: ${IP})"
