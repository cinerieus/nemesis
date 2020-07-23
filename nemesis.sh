#!/bin/bash
printf "Running Arch Nemesis install script...\n"
read -p "Do you want to continue? [Y/N]" continue
if echo "$continue" | grep -iqFv y; then
	exit 0
fi

#### Options ####
# read -p "Hostname: " hostname
hostname="ikaros"
# read -p "Username: " username
username="cinereus"
# read -p "Server Install? [Y/N] " server
server="Y"
# read -p "Use Encryption? [Y/N] " encryption
encryption="Y"
#read -p "Secure Boot? [Y/N] " secureboot
secureboot="N"

#### Keyboard ####
loadkeys uk

#### Internet Check  ####
printf "\n\nChecking connectivity...\n"
if [[ $(ping -W 3 -c 2 archlinux.org) != *" 0%"* ]]; then
	read -p "Network Error, Use WiFi? [Y/N] " wifi
	if echo "$wifi" | grep -iqF y; then
		device=$(ip link | grep "wl"* | grep -o -P "(?= ).*(?=:)" | sed -e "s/^[[:space:]]*//" | cut -d$'\n' -f 1)
		printf "\nInstall using WiFi...\n"
		read -p "SSID: " ssid
		read -rsp "WiFi Password: " wifipass
		iwctl --passphrase "$wifipass" station "$device" connect "$ssid"
	else
		printf "\nNetwork error, Exiting...\n"
		exit 0
	fi
fi
if [[ $(ping -W 3 -c 2 archlinux.org) != *" 0%"* ]]; then
	printf "\nNetwork error, Exiting...\n"
	exit 0
fi

#### Time ####
timedatectl set-ntp true

#### Partitioning (LVM on LUKS) ####
printf "\n\nPartitioning disk(s)...\n"
disk=$(sudo fdisk -l | grep "dev" | grep -o -P "(?=/).*(?=:)" | cut -d$'\n' -f1)
wipefs -af $disk
echo "label: gpt" | sfdisk --force $disk
sfdisk --force $disk << EOF
,260M,U,*
;
EOF

#### Encryption ####
if echo "$encryption" | grep -iqF y; then
	printf "\n\nEncrpting primary partition...\n"
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
printf "\n\nConfiguring LVM and formating partitions...\n"
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
printf "\n\nPackstrap packages...\n"
# More packages can be added here
if echo "$server" | grep -iqF y; then
	pacstrap /mnt base linux lvm2 grub efibootmgr vim sudo nmap openssh tcpdump
else
	pacstrap /mnt base linux linux-firmware lvm2 grub efibootmgr intel-ucode vim sudo nmap openssh tcpdump
fi

#### Config ####
# Fstab
printf "\n\nGenerating fstab..."
genfstab -U /mnt >> /mnt/etc/fstab

#### Create stage 2 script ####
printf "\n\nCreating stage 2 script..."
echo "
#!/bin/bash
hostname=$hostname
username=$username
server=$server
encryption=$encryption
secureboot=$secureboot
disk=$disk" > /mnt/nemesis.sh

echo '
# Time Zone
printf "\n\nSetting timezone...\n"
ln -sf /usr/share/zoneinfo/Europe/London /etc/localtime
hwclock --systohc

# Localization
printf "\nConfiguring locale...\n"
echo en_GB.UTF-8 UTF-8 > /etc/locale.gen
locale-gen
echo LANG=en_GB.UTF-8 > /etc/locale.conf
echo KEYMAP=uk > /etc/vconsole.conf

# Network Config
printf "\nConfiguring networks...\n"
echo $hostname > /etc/hostname
echo -e "127.0.0.1\tlocalhost\n::1\t\tlocalhost" >> /etc/hosts
if echo "$server" | grep -iqF y; then
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
	echo "
	[Match]
	Name=wlp*
	Name=wlan*

	[Network]
	DHCP=yes
	IPv6PrivacyExtensions=yes

	[DHCP]
	RouteMetric=20" > /etc/systemd/network/25-wireless.network
else
	systemctl enable NetworkManager
fi

#### Initramfs ####
printf "n\nSetting up initramfs...\n"
if echo "$encryption" | grep -iqF y; then
	echo "HOOKS=(base udev autodetect keyboard keymap consolefont modconf block encrypt lvm2 filesystems fsck)" > /etc/mkinitcpio.conf
else
	echo "HOOKS=(base udev autodetect keyboard keymap consolefont modconf block lvm2 filesystems fsck)" > /etc/mkinitcpio.conf
fi
mkinitcpio -P

#### Bootloader ####
printf "\n\nConfiguring bootloader...\n"
grub-install --target=x86_64-efi --efi-directory=/boot --bootloader-id=GRUB
if echo "$encryption" | grep -iqF y; then
	cryptdevice=$(lsblk -dno UUID ${disk}2)
	echo GRUB_CMDLINE_LINUX="cryptdevice=UUID=$cryptdevice:cryptlvm" > /etc/default/grub
fi
grub-mkconfig -o /boot/grub/grub.cfg

#### User Setup ####
printf "\n\nUser setup...\n"
echo "
# /etc/profile

# Set our umask
umask 002

# Append our default paths
appendpath () {
    case ":$PATH:" in
        *:"$1":*)
            ;;
        *)
            PATH="${PATH:+$PATH:}$1"
    esac
}

appendpath "/usr/local/sbin"
appendpath "/usr/local/bin"
appendpath "/usr/bin"
unset -f appendpath

export PATH

# Load profiles from /etc/profile.d
if test -d /etc/profile.d/; then
        for profile in /etc/profile.d/*.sh; do
                test -r "$profile" && . "$profile"
        done
        unset profile
fi

# Source global bash config, when interactive but not posix or sh mode
if test "$BASH" &&\
   test "$PS1" &&\
   test -z "$POSIXLY_CORRECT" &&\
   test "${0#-}" != sh &&\
   test -r /etc/bash.bashrc
then
        . /etc/bash.bashrc
fi

# Termcap is outdated, old, and crusty, kill it.
unset TERMCAP

# Man is much better than us at figuring this out
unset MANPATH" > /etc/profile

read -sp "$username password: " password
read -sp "root password: " rootpassword
echo "$password" | passwd --stdin $username
echo "%wheel	ALL=(ALL) ALL" >> /etc/sudoers
useradd -m -G wheel $username
echo "$password" | passwd --stdin $username
echo "$rootpassword" | passwd --stdin root

#### Custom Packages ####
printf "\n\nInstalling packages...\n"
if echo "$server" | grep -iqFv y; then
	pacman --noconfirm -S mesa lib32-mesa vulkan-intel alsa-utils x86-input-libinput xorg-xinput bluez bluez-utils networkmanager
fi
#########################' >> /mnt/nemesis.sh


# Chroot and run
#################
printf "\n\nChrooting and running stage 2..."
chmod +x /mnt/nemesis.sh
arch-chroot /mnt ./nemesis.sh
printf "\n\nCleaning up..."
rm /mnt/nemesis.sh
printf "\n\nDone! - Rebooting...\n"
#reboot
#################
