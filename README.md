# Nemesis

Automated Arch Linux build system. Builds fully configured VMs (QEMU/Proxmox) and provisions VPS instances (Vultr/DigitalOcean) with a single command.

What you get: Arch Linux with GNOME desktop, Catppuccin theming, fish shell, neovim, 30+ pentesting tools, hardened SSH, firewall, fail2ban, DNS-over-TLS, ZeroTier VPN, and automatic updates.

## Prerequisites

Install these on your **local machine** (the machine you run commands from):

```bash
# Arch Linux / WSL2
sudo pacman -S ansible terraform python-yaml

# Or with your package manager of choice:
# - ansible       (pip install ansible)
# - terraform     (hashicorp.com/terraform)
# - python-yaml   (pip install pyyaml) — needed by Makefile to read nemesis.yml
# - packer        (only needed for Proxmox template builds)
```

Your **remote KVM host** needs: `libvirtd`, `qemu`, `ovmf` (UEFI firmware), and SSH access from your local machine.

## Quick Start

### 1. Clone and configure

```bash
git clone <repo-url> nemesis && cd nemesis
```

Edit the two config files:

```bash
# Main config - set your username, SSH keys, VPN, etc.
vim nemesis.yml

# Passwords - change these before doing anything else
vim secrets.yml
```

### 2. Add your SSH keys

Put your public keys in `config/ssh/authorized_keys`:

```bash
echo "ssh-ed25519 AAAA... you@host" > config/ssh/authorized_keys
```

Or add them to `ssh_public_keys` in `nemesis.yml` -- both methods work and are combined.

### 3. Encrypt your secrets

```bash
make vault-encrypt
```

This encrypts `secrets.yml` with Ansible Vault. You'll be prompted to set a vault password. Remember it -- you'll need it for every build.

To avoid typing the password every time, create a `.vault-pass` file:

```bash
echo "your-vault-password" > .vault-pass
chmod 600 .vault-pass
```

### 4. Build

```bash
# See all available commands
make help
```

## Build Targets

### Create a VM on a remote KVM host

Creates a VM on your remote QEMU/KVM server (with Cockpit/libvirt), boots it from the Arch cloud image, then configures it over SSH with Ansible. Everything runs remotely — nothing needs KVM locally.

**Prerequisites on the KVM host:**
- `libvirtd` running (Cockpit's "Virtual Machines" module uses this)
- SSH access from your machine to the KVM host
- OVMF/UEFI firmware installed (`/usr/share/OVMF/`)

**Setup:**

1. Make sure you can SSH to your KVM host without a password (key-based auth):
   ```bash
   ssh-copy-id user@your-kvm-host
   ```

2. Set the connection URI in `nemesis.yml`:
   ```yaml
   libvirt_uri: "qemu+ssh://user@192.168.1.100/system"
   ```

3. Build:
   ```bash
   make vm-kvm
   ```

This runs: Terraform connects to libvirt over SSH -> creates a VM from the Arch cloud image -> cloud-init sets up SSH -> Ansible configures everything (desktop, tools, hardening, the lot).

The VM will show up in Cockpit under Virtual Machines. SSH in with the IP Terraform prints, or connect via RDP on port 3389.

To tear it down:

```bash
make destroy-vm
```

### Build a Proxmox template

Same concept but for Proxmox — Packer connects to the Proxmox API remotely, boots the Arch ISO, installs, and creates a template. Fill in the Proxmox settings in `nemesis.yml`:

```yaml
proxmox_url: "https://proxmox.example.com:8006/api2/json"
proxmox_token: "user@pam!token=secret-value"
proxmox_node: "pve"
proxmox_storage: "local-lvm"
```

```bash
make vm-proxmox
```

### Provision a Vultr VPS

Creates a Vultr instance via API and configures it over SSH. Set your API key in `nemesis.yml`:

```yaml
vultr_api_key: "your-key"
vps_region: "ewr"        # Vultr region code
vps_plan: "vc2-1c-1gb"   # Vultr plan code
```

```bash
make vps-vultr
```

This runs: `terraform apply` (creates instance) -> generates Ansible inventory -> runs the VPS playbook (headless -- no desktop/RDP).

### Provision a DigitalOcean VPS

Same flow but for DigitalOcean:

```yaml
digitalocean_token: "your-token"
```

```bash
make vps-do
```

### Configure an existing machine

Already have a machine running Arch? Point Ansible at it directly:

```bash
# Configure as a VPS (headless: shell, tools, hardening, firewall, VPN)
make configure HOST=10.0.0.5 PLAY=vps

# Configure as a VM (full desktop: GNOME, RDP, bootloader, everything)
make configure HOST=10.0.0.5 PLAY=vm
```

The target machine needs: Arch Linux installed, root SSH access, and python3.

## Configuration

Everything is in two files. You never need to dig into roles or group_vars.

### nemesis.yml

This is the only file you need to edit. The top half has system settings, the bottom half has every package that gets installed — add, remove, or comment out lines to customise your build.

**System settings:**

| Setting | Default | Description |
|---------|---------|-------------|
| `hostname` | `""` (auto) | Leave empty to auto-generate `DESKTOP-XXXXXXX` |
| `username` | `"user"` | Non-root user account |
| `ssh_public_keys` | `[]` | Extra SSH keys (appended to `config/ssh/authorized_keys`) |
| `vpn_provider` | `"zerotier"` | `"zerotier"` or `"tailscale"` |
| `zerotier_network_id` | `""` | ZeroTier network to join (leave empty to skip VPN) |
| `zerotier_api_token` | `""` | Optional: auto-authorize the node |
| `luks_enabled` | `false` | Full-disk encryption (VM only) |
| `secureboot_enabled` | `true` | Secure Boot kernel signing (VM only) |
| `disk_size` | `"50G"` | VM disk size |
| `vm_memory` | `4096` | VM RAM in MB |
| `vm_cpus` | `2` | VM CPU cores |
| `hypervisor` | `"qemu"` | `"qemu"`, `"proxmox"`, or `"vmware"` |
| `wallpaper_url` | wallhaven URL | Desktop wallpaper (VM only) |
| `dns_over_tls_server` | `"1.1.1.1"` | Upstream DNS server |
| `fail2ban_bantime` | `"1h"` | How long to ban IPs |
| `fail2ban_maxretry` | `3` | Failed attempts before ban |
| `auto_updates` | `true` | Daily `pacman -Syu` via systemd timer |
| `ipv6_enabled` | `false` | Disable IPv6 at kernel level when false |

**Package lists** (all in `nemesis.yml`, all editable):

| List | What it controls |
|------|------------------|
| `base_packages` | CLI utilities — wget, curl, jq, htop, bat, ripgrep, etc. |
| `shell_packages` | Shell tooling — fish, starship, neovim, tmux |
| `font_packages` | Fonts — Noto, FiraMono Nerd |
| `gnome_packages` | GNOME desktop + GDM (VM only) |
| `gnome_extensions_pacman` | GNOME extensions from official repos (VM only) |
| `gnome_extensions_aur` | GNOME extensions from AUR (VM only) |
| `desktop_apps` | Desktop applications — kitty, firefox, etc. (VM only) |
| `catppuccin_aur_packages` | Catppuccin theme cursors from AUR (VM only) |
| `catppuccin_pacman_packages` | Icon themes from official repos (VM only) |
| `catppuccin_folders_aur` | Papirus folder colors from AUR (VM only) |
| `security_packages` | Pentesting tools from BlackArch/pacman |
| `security_packages_aur` | Pentesting tools from AUR |
| `extra_packages` | Anything else you want |
| `extra_security_packages` | Additional pentesting tools beyond the defaults |

Only packages required for the system to function (`sudo`, `base-devel`, `git`, `python`, `networkmanager`) are hardcoded in the roles. Everything else is in `nemesis.yml` so you can see and edit it in one place.

### secrets.yml

Passwords. Encrypt this with `make vault-encrypt`.

| Setting | Description |
|---------|-------------|
| `user_password` | Sudo/console password for the user account |
| `rdp_password` | RDP login password (VM only) |
| `luks_password` | Disk encryption passphrase (only if `luks_enabled: true`) |

## What Gets Installed

VM builds install everything. VPS builds skip the desktop/bootloader/virtualization/RDP roles.

### Staged tools (downloaded to `/opt/workspace/`)

These are always downloaded regardless of packages:

- `wordlists/rockyou.txt`
- `tools/chisel/` — linux + windows binaries
- `tools/peass/` — linpeas.sh, winPEASx64.exe
- `tools/ghostpack/` — compiled Ghostpack binaries
- `tools/sliver/` — sliver-server + sliver-client

### System hardening (always applied)

- Kernel sysctl hardening (pointer hiding, dmesg restrict, reverse path filtering, IPv6 disable)
- fail2ban on SSH
- DNS-over-TLS via systemd-resolved
- auditd
- UFW firewall (SSH/RDP restricted to primary + VPN interfaces)
- Automatic daily updates via systemd timer

## Managing Secrets

```bash
# First time: encrypt secrets.yml
make vault-encrypt

# Edit encrypted secrets
make vault-edit

# Temporarily decrypt (careful - don't commit this)
make vault-decrypt
```

If you have a `.vault-pass` file in the project root, it's used automatically. Otherwise you'll be prompted for the password on every build.

## Validation

```bash
# Lint Ansible playbooks
make lint

# Dry run (no changes, just show what would happen)
make check-vm
make check-vps

# Validate Packer templates
make validate-packer

# Validate Terraform modules
make validate-terraform
```

## Destroying Infrastructure

```bash
# Destroy a KVM VM on the remote host
make destroy-vm

# Tear down a Vultr VPS
make destroy-vultr

# Tear down a DigitalOcean VPS
make destroy-do

# Remove local build artifacts
make clean
```

## Project Structure

```
nemesis/
├── Makefile                        # All build commands
├── nemesis.yml                     # Your config (edit this)
├── secrets.yml                     # Passwords (vault-encrypted)
├── ansible/
│   ├── ansible.cfg
│   ├── inventory/hosts.yml
│   ├── group_vars/                 # Default values (overridden by nemesis.yml)
│   ├── playbooks/
│   │   ├── vm.yml                  # Full desktop build
│   │   └── vps.yml                 # Headless server build
│   └── roles/
│       ├── base/                   # System basics, pacman, user, hostname
│       ├── shell/                  # fish, starship, neovim, tmux
│       ├── desktop/                # GNOME, extensions, theming
│       ├── ssh/                    # sshd hardening
│       ├── bootloader/             # GRUB, LUKS, Secure Boot
│       ├── virtualization/         # Guest agents
│       ├── rdp/                    # GNOME Remote Desktop
│       ├── security_tools/         # Pentesting packages + staged tools
│       ├── firewall/               # UFW
│       ├── hardening/              # sysctl, fail2ban, DNS-over-TLS
│       ├── vpn/                    # ZeroTier / Tailscale
│       └── updates/                # Auto-update timer
├── packer/
│   └── archlinux-proxmox.pkr.hcl  # Proxmox template builder (for later)
├── terraform/
│   ├── libvirt/                    # Remote KVM/QEMU VM provisioning
│   ├── vultr/                      # Vultr VPS provisioning
│   ├── digitalocean/               # DigitalOcean provisioning
│   └── scripts/generate-inventory.sh
└── config/
    ├── dotfiles/                   # fish, starship, neovim, tmux, kitty configs
    ├── themes/                     # Catppuccin theme zips (add your own)
    ├── dconf/gnome.dconf           # GNOME settings dump
    ├── ssh/authorized_keys         # Your SSH public keys
    └── hooks/                      # Pacman hooks (Secure Boot signing)
```

## Customising

### Packages

Every installable package is listed in `nemesis.yml`. Open it and scroll to the Packages section. To add, remove, or comment out a package, just edit the relevant list:

```yaml
# Add a base utility
base_packages:
  - wget
  - curl
  - jq
  - your-tool-here          # <-- add

# Remove a desktop app you don't want
desktop_apps:
  - kitty
  - thunar
  # - firefox               # <-- commented out
  # - libreoffice-fresh      # <-- commented out

# Add a security tool
security_packages:
  - nmap
  - metasploit
  - your-tool-here          # <-- add

# Or put extras in the catch-all lists
extra_packages:
  - neofetch
  - your-random-package

extra_security_packages:
  - burpsuite
```

### Change dotfiles

Edit files in `config/dotfiles/` directly. They're copied as-is to the target machine:

- `config.fish` -- fish shell config
- `starship.toml` -- prompt theme
- `init.lua` -- neovim config (lazy.nvim plugins)
- `tmux.conf` -- tmux config
- `kitty.conf` -- kitty terminal config

### Change GNOME settings

The file `config/dconf/gnome.dconf` contains all GNOME settings. To capture your own:

1. Configure GNOME the way you like on a running system
2. Run `dconf dump / > config/dconf/gnome.dconf`
3. Rebuild

### Add theme files

Drop Catppuccin theme zips into `config/themes/`:

- `catppuccin-gnomeshell.zip` -- GNOME Shell theme
- `catppuccin-grub.zip` -- GRUB bootloader theme

These are extracted automatically during the build if present.

### Change the wallpaper

Either set `wallpaper_url` in `nemesis.yml` to a direct image URL, or replace the file manually after build at `/opt/workspace/backgrounds/`.
