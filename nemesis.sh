#!/bin/bash

#### Options ####
hostname=""
username=""
# Server Install? [Y/N]
server="Y"
# Use WiFi? [Y/N]
wifi="N"
# Use Encryption? [Y/N]
encryption="Y"
#Use Secure Boot? [Y/N]
secureboot="N"

echo "Running Arch install script..."
read -p "Do you want to continue? [Y/N]" continue
if echo $continue | grep -iqFv y; then
	exit 0
fi

#### Keyboard ####
loadkeys uk

#### Internet Check  ####
if echo $wifi | grep -iqF y; then
	device=$(ip link | grep "wl"* | grep -o -P "(?= ).*(?=:)" | sed -e "s/^[[:space:]]*//" | cut -d$'\n' -f 1)
	echo "Using WiFi..."
	read -p "SSID: " ssid
	read -sp "WiFi Password: " wifipass
	iwctl --passphrase $wifipass station $device connect $ssid
fi
if [[ $(ping -W 3 -c 2 archlinux.org) != *" 0%"* ]]; then
	echo "Network Error, Exiting..."
	exit 0
fi

#### Time ####
timedatectl set-ntp true

#### Partitioning (LVM on LUKS) ####
disk=$(sudo fdisk -l | grep "dev" | grep -o -P "(?=/).*(?=:)" | cut -d$'\n' -f1)
wipefs -af $disk
echo "label: gpt" | sfdisk --force $disk
sfdisk --force $disk << EOF
,260M,U,*
;
EOF

#### Encryption ####
if echo $encryption | grep -iqF y; then
	read -sp 'LUKS Encryption Passphrase: ' encpass
	echo $encpass | cryptsetup -q luksFormat "${disk}2"
	echo $encpass | cryptsetup open "${disk}2" cryptlvm -
	pvcreate /dev/mapper/cryptlvm
	vgcreate lvgroup /dev/mapper/cryptlvm
else
	pvcreate "${disk}2"
	vgcreate lvgroup "${disk}2"
fi

#### LVM/Format /root /swap ####
lvcreate -L 4G lvgroup -n swap
lvcreate -l 100%FREE lvgroup -n root
mkfs.ext4 /dev/lvgroup/root
mkswap /dev/lvgroup/swap
mount /dev/lvgroup/root /mnt
swapon /dev/lvgroup/swap

#### Format /boot ####
mkfs.fat -F 32 "${disk}1"
mkdir /mnt/boot
mount "${disk}1" /mnt/boot

#### Installation ####
# More packages can be added here
if echo $server | grep -iqF y; then
	pacstrap /mnt base linux lvm2 grub efibootmgr
else
	pacstrap /mnt base linux linux-firmware lvm2 networkmanager intel-ucode
fi

#### Config ####
# Fstab
genfstab -U /mnt >> /mnt/etc/fstab

#### Create stage 2 script ####
echo "
hostname = $hostname
username = $username
server = $server
wifi = $wifi
encryption = $encryption
secureboot = $secureboot" > /mnt/nemesis.sh

echo '
# Time Zone
ln -sf /usr/share/zoneinfo/Europe/London /etc/localtime
hwclock --systohc

# Localization
echo en_GB.UTF-8 UTF-8 > /etc/locale.gen
locale-gen
echo LANG=en_GB.UTF-8 > /etc/locale.conf
echo KEYMAP=uk > /etc/vconsole.conf

# Network Config
echo $hostname > /etc/hostname
echo -e "127.0.0.1\tlocalhost\n::1\t\tlocalhost" >> /etc/hosts
if echo $server | grep -iqF y; then
	systemctl enable systemd-networkd
	systemctl enable systemd-resolved
	echo "
	[Match]
	Name=en*
	Name=eth*

	[Network]
	DHCP=yes
	IPv6PrivacyExtensions=yes

	[DHCP]
	RouteMetric=10" > /etc/systemd/network/20-wired.network
	if echo $wifi| grep -iqF y; then
		pacman -S wpa_supplicant --noconfim >/dev/null
		echo "
		[Match]
		Name=wlp*
		Name=wlan*

		[Network]
		DHCP=yes
		IPv6PrivacyExtensions=yes

		[DHCP]
		RouteMetric=20" > /etc/systemd/network/25-wireless.network
		read -p "SSID: " ssid
		read -sp "WiFi Password: " wifipass
		device=$(ip link | grep "wl"* | grep -o -P "(?= ).*(?=:)" | sed -e "s/^[[:space:]]*//" | cut -d$'\'\\n\'' -f 1)
		#iwctl --passphrase $wifipass station $device connect $ssid
	fi
else
	systemctl enable NetworkManager
fi

#### Initramfs ####
if echo $encryption | grep -iqF y; then
	echo HOOKS=(base udev autodetect keyboard keymap consolefont modconf block encrypt lvm2 filesystems fsck) > /etc/mkinitcpio.conf
	mkinitcpio -P
fi

#### Bootloader ####
if echo $server | grep -iqF y; then
	grub-install --target=x86_64-efi --efi-directory=/boot --bootloader-id=GRUB
	if echo $encryption | grep -iqF y; then
		cryptdevice=$(lsblk -dno UUID ${disk}2)
		echo cryptdevice=UUID=$cryptdevice:cryptlvm root=/dev/lvgroup/root > /etc/default/grub
	fi
	grub-mkconfig -o /boot/grub/grub.cfg
fi' >> /mnt/nemesis.sh

# Chroot and run
#################
arch-chroot /mnt ./nemesis.sh
#################
