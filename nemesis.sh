#!/bin/bash
printf "Running Arch Nemesis install script...\n"
read -p "Do you want to continue? [Y/N]" continue
if echo "$continue" | grep -iqFv y; then
        exit 0
fi

#### Options ####
read -p "Hostname: " hostname
read -p "Username: " username
password="Ch4ngeM3!"
tzone="Europe/London"
read -p "Attack Build? [Y/N] " extra
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
        read -p "SSH key url: " sshkeyurl
        secureboot="N"
else
        isstatic="N"
        address=""
        gateway=""
        dns=""
        sshkeyurl=""
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
timedatectl set-timezone "$tzone"
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
        pacstrap /mnt base linux lvm2 grub efibootmgr neovim sudo openssh git
else
	pacstrap /mnt base linux linux-firmware lvm2 grub efibootmgr neovim sudo openssh git
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
password=$password
extra=$extra
server=$server
isstatic=$isstatic
address=$address
gateway=$gateway
dns=$dns
sshkeyurl=$sshkeyurl
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
export LANG=en_GB.UTF-8
echo KEYMAP=uk > /etc/vconsole.conf

# Network Config
printf "\nConfiguring networks...\n"
echo $hostname > /etc/hostname
echo -e "127.0.0.1\tlocalhost\n::1\t\tlocalhost" >> /etc/hosts
if echo "$server" | grep -iqF y; then
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
	systemctl enable systemd-networkd
        systemctl enable systemd-resolved
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
grub-install --target=x86_64-efi --efi-directory=/boot --bootloader-id=GRUB --removable
#grub-install --target=x86_64-efi --efi-directory=/boot --bootloader-id=GRUB
if echo "$encryption" | grep -iqF y; then
        cryptdevice=$(lsblk -dno UUID ${disk}2)
        echo GRUB_CMDLINE_LINUX="cryptdevice=UUID=$cryptdevice:cryptlvm" > /etc/default/grub
fi
grub-mkconfig -o /boot/grub/grub.cfg

#### User Setup ####
printf "\n\nUser setup...\n"
echo "%wheel    ALL=(ALL) ALL" >> /etc/sudoers
useradd -m -G users,wheel $username
echo -e "$password\n$password" | passwd $username

#### SSH setup ####
if echo "$server" | grep -iqF y; then
        systemctl enable sshd
        if [ -n "$sshkeyurl" ]; then
                echo "
                HostKey /etc/ssh/ssh_host_ed25519_key
                PermitRootLogin no
                PasswordAuthentication no" >> /etc/ssh/sshd_config
		sudo -Hu $username mkdir /home/$username/.ssh
		sudo -Hu $username chmod 750 /home/$username/.ssh
                sudo -Hu $username curl $sshkeyurl > /home/$username/.ssh/authorized_keys
		#sudo -Hu $username chmod 600 /home/$username/.ssh/authorized_keys
        else
                echo "
                HostKey /etc/ssh/ssh_host_ed25519_key
                PermitRootLogin no" >> /etc/ssh/sshd_config
        fi
fi

#### Customization ####
printf "\n\nInstalling packages...\n"

## shared folder ##
umask 002
chgrp users /opt
chmod 775 /opt
chmod g+s /opt
cd /opt

## blackarch repos ##
printf "\n\nInstalling Blackarch repos... \n"
curl https://blackarch.org/strap.sh | sh
echo "
[multilib]
Include = /etc/pacman.d/mirrorlist" >> /etc/pacman.conf
pacman --noconfirm -Syu

## yay installation ##
#printf "\n\nInstalling Yay... \n"
#git clone https://aur.archlinux.org/yay.git
#cd /opt/yay
#sudo -u $username makepkg -si --noconfirm
#cd /opt
#yay --noconfirm -Sy

## build specific packages ##
if echo "$server" | grep -iqFv y; then
	#pacman --noconfirm -S alsa-utils bluez bluez-utils networkmanager xorg-xinput xorg-server plasma kvantum-qt5 latte-dock dolphin kwrite gwenview konsole spectacle chromium firefox
	#egl-wayland
	pacman --noconfirm -S alsa-utils plasma-meta plasma-wayland-session kvantum-qt5 dolphin kwrite kate gwenview konsole spectacle chromium firefox
	pacman --noconfirm -S pipewire pipewire-alsa pipewire-pulse pipewire-jack
	systemctl enable NetworkManager
	systemctl enable sddm
else
        pacman --noconfirm -S open-vm-tools
fi

## intel ##
#pacman --noconfirm -S intel-ucode mesa lib32-mesa vulkan-intel  

## amd ##
#pacman --noconfirm -S amd-ucode mesa lib32-mesa amdvlk lib32-amdvlk

## utils ##
pacman --noconfirm -S yay base-devel gnu-netcat socat python python-pip unzip p7zip go cifs-utils wget tcpdump openvpn cowsay lolcat fortune-mod neofetch toilet cmatrix asciiquarium
yay --noconfirm -Sy

## attack build - extra tools ##
if echo "$extra" | grep -iqF y; then
	## tools ##
	pacman --noconfirm -S nmap impacket metasploit sqlmap john medusa ffuf feroxbuster nullinux linux-smart-enumeration enum4linux seclists ad-ldap-enum ntdsxtract
	#sudo -Hu $username yay --noconfirm -S libesedb
	sudo -Hu $username pip install as3nt --no-input --user

	## extra ##
	mkdir /opt/wordlists /opt/linux /opt/windows
	cd /opt/wordlists
	wget http://downloads.skullsecurity.org/passwords/rockyou.txt.bz2
	bzip2 -d rockyou.txt.bz2
	cd /opt
	git clone https://github.com/SecWiki/linux-kernel-exploits.git /opt/linux/linux-kernel-exploits
	git clone https://github.com/andrew-d/static-binaries.git /opt/linux/static-binaries
	
	git clone https://github.com/SecWiki/windows-kernel-exploits.git /opt/windows/windows-kernel-exploits
	git clone https://github.com/interference-security/kali-windows-binaries.git /opt/windows/binaries
	git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries.git /opt/windows/ghostpack_binaries
	
	git clone https://github.com/carlospolop/PEASS-ng.git /opt/peassng
	git clone https://github.com/dirkjanm/krbrelayx.git /opt/windows/krbrelayx
	
	echo "
## Todo ##
- Change your password from Ch4ngeM3!
- Run finish.sh

## fun ##
- cowsay
- fortune
- lolcat
- toilet
- cmatrix 
- asciiquarium
- neofetch

## Tools ##
- nmap
- socat
- netcat
- openvpn
- impacket
- metasploit
- sqlmap
- john-the-ripper
- medusa
- ffuf
- feroxbuster
- nullinux
- enum4linux
- esedbexport
- ntdsxtract

## Scripts ##
- linux-smart-enumeration
- ad-ldap-enum
- PEASS-ng
- krbrelayx

## exploits ##
- linux kernel: /opt/linux/linux-kernel-exploits
- linux static binaries: /opt/linux/static-binaries
- windows kernel: /opt/windows/windows-kernel-exploits
- windows binaries: /opt/windows/binaries
- windows ghostpack binaries: /opt/windows/ghostpack_binaries

## Locations ##
- /usr/share and /opt
- Tools and scripts are located in /usr/share & /opt
- SecLists: /usr/share/seclists
- rockyou.txt: /opt/wordlists/rockyou.txt
	" > /home/$username/readme.txt
else
	echo "
## Todo ##
- Change your password from Ch4ngeM3!
- Run finish.sh

## fun ##
- cowsay
- fortune
- lolcat
- toilet
- cmatrix 
- asciiquarium
- neofetch
	" > /home/$username/readme.txt
fi

## finishing touches ##
printf "\n\nFinishing touches... \n"

if echo "$server" | grep -iqF y; then
	echo -e "
#\x21/bin/bash
sudo rm /etc/resolv.conf && sudo ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf &&
nvim +:PlugInstall +:qa &&
#cd /opt/yay && makepkg -si && cd ~ &&
yay -S libesedb &&
rm finish.sh
	" > /home/$username/finish.sh
	
	echo -e "#\x21/bin/bash" > /etc/motd.sh
	echo "echo \"$(toilet -f pagga -w 110 -F border $hostname | lolcat -ft)\"" >> /etc/motd.sh
	echo "echo '' ; neofetch ; echo '' ; fortune | cowsay -f head-in -W 110 | lolcat -f ; echo ''" >> /etc/motd.sh
	chmod +x /etc/motd.sh
	echo "session    optional   pam_exec.so          stdout /etc/motd.sh" >> /etc/pam.d/system-login
else
	echo -e "
#\x21/bin/bash
nvim +:PlugInstall +:qa &&
cd /opt/yay && makepkg -si && cd ~ &&
yay -S libesedb &&
rm finish.sh
	" > /home/$username/finish.sh
fi

chmod +x /home/$username/finish.sh

sudo -Hu $username curl https://raw.githubusercontent.com/cinerieus/nemesis/master/bashrc -o /home/$username/.bashrc
sudo -Hu $username curl https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim -o /home/$username/.local/share/nvim/site/autoload/plug.vim --create-dirs
sudo -Hu $username curl https://raw.githubusercontent.com/cinerieus/nemesis/master/init.vim -o /home/$username/.config/nvim/init.vim --create-dirs

cp /home/$username/.bashrc /root/
mkdir -p /root/.local/share/nvim/site/autoload && cp /home/$username/.local/share/nvim/site/autoload/plug.vim /root/.local/share/nvim/site/autoload/plug.vim
mkdir -p /root/.config/nvim && cp /home/$username/.config/nvim/init.vim /root/.config/nvim/init.vim

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
printf "\n\nDon't forget to change your password!"
printf "\n\nRebooting..."
sleep 5
reboot
#################
