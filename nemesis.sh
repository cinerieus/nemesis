#!/bin/bash
printf "Running Arch Nemesis install script...\n"
read -p "Do you want to continue? [Y/N]" continue
if echo "$continue" | grep -iqF n; then
        exit 0
fi

#### Options ####
read -p "Hostname: " hostname
read -p "Username: " username
read -p "Disk Encryption? [Y/N] " encryption
read -p "Server Install? [Y/N] " server
if echo "$server" | grep -iqF y; then
        read -p "Static IP? [Y/N] " isstatic
                if echo "$isstatic" | grep -iqF y; then
                        read -p "IP Address (CIDR): " address
                        read -p "Gateway: " gateway
                        read -p "DNS: " dns
                else
                        address=""
                        gateway=""
                        dns=""
                fi
        read -p "SSH key: " sshkey
        secureboot="N"
else
        isstatic="N"
        address=""
        gateway=""
        dns=""
        sshkey=""
        read -p "Secure Boot? [Y/N] " secureboot
fi

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
	pacstrap /mnt base linux linux-firmware lvm2 grub efibootmgr vim sudo nmap openssh tcpdump
        #pacstrap /mnt base linux linux-firmware lvm2 grub efibootmgr intel-ucode vim sudo nmap openssh tcpdump
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
isstatic=$isstatic
address=$address
gateway=$gateway
dns=$dns
sshkey=$sshkey
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
        if echo "$isstatic" | grep -iqF y; then
                echo "
                [Match]
                Name=en*
                Name=eth*

                [Network]
                Address=$address
                Gateway=$gateway
                DNS=$dns" > /etc/systemd/network/20-wired.network
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
        fi
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
read -sp "$username password: " password
echo
read -sp "$username confirm password: " password2
while [ "$password" != "$password2" ]; do
	printf "\n\bPlease try again\n"
	read -sp "$username password: " password
	echo
	read -sp "$username confirm password: " password2
done
echo "%wheel    ALL=(ALL) ALL" >> /etc/sudoers
useradd -m -G wheel $username
echo -e "$password\n$password" | passwd $username

#### SSH setup ####
if echo "$server" | grep -iqF y; then
        systemctl enable sshd
        if [ -n "$sshkey" ]; then
                echo "
                HostKey /etc/ssh/ssh_host_ed25519_key
                PermitRootLogin no
                PasswordAuthentication no" >> /etc/ssh/sshd_config
		sudo -u $username mkdir ~/.ssh
		sudo -u $username chmod 750 ~/.ssh
                sudo -u $username echo "$sshkey" > ~/.ssh/authorized_keys
		sudo -u $username chmod 600 ~/.ssh/authorized_keys
        else
                echo "
                HostKey /etc/ssh/ssh_host_ed25519_key
                PermitRootLogin no" >> /etc/ssh/sshd_config
        fi
fi

#### Customization ####
if echo "$server" | grep -iqF n; then
	printf "\n\nInstalling packages...\n"
	echo "
	[multilib]
	Include = /etc/pacman.d/mirrorlist" >> /etc/pacman.conf
	pacman -Sy
        #pacman --noconfirm -S mesa lib32-mesa vulkan-intel 
	pacman --noconfirm -S alsa-utils bluez bluez-utils networkmanager xorg-xinput xorg-server plasma kvantum-qt5 latte-dock dolphin kwrite gwenview kitty spectacle chromium firefox
	systemctl enable NetworkManager
	systemctl enable sddm
else
	printf "\n\nInstalling packages...\n"
        pacman --noconfirm -S open-vm-tools
fi

pacman --noconfirm -S base-devel gnu-netcat socat netstat-nat git python python-pip unzip p7zip go cifs-utils openvpn

printf "\n\nInstalling Blackarch repos... \n"
cd /opt
curl https://blackarch.org/strap.sh | sh
pacman --noconfirm -Sy

printf "\n\nInstalling Yay... \n"
git clone https://aur.archlinux.org/yay.git
chown -R $username:$username yay
cd yay
sudo -u $username makepkg si
cd /

printf "\n\nFinishing touches... \n"
sudo -u $username curl https://raw.githubusercontent.com/cinerieus/nemesis/master/bashrc -o /home/$username/.bashrc
sudo -u $username curl https://raw.githubusercontent.com/cinerieus/nemesis/master/vimrc -o /home/$username/.vimrc
sudo -u $username git clone https://github.com/VundleVim/Vundle.vim.git /home/$username/.vim/bundle/Vundle.vim
#sudo -u $username vim +PluginInstall +qall
pacman --noconfirm -Syu

printf "\nDone.\n"
#######################' >> /mnt/nemesis.sh

# Chroot and run
#################
printf "\n\nChrooting and running stage 2..."
chmod +x /mnt/nemesis.sh
arch-chroot /mnt ./nemesis.sh
printf "\n\nCleaning up..."
rm /mnt/nemesis.sh
printf "\n\nDone! - Rebooting..."
reboot
#################
