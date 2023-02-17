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
read -p "BIOS Boot Mode? [Y/N] " legacyboot
if echo "$legacyboot" | grep -iqF n; then
        read -p "Secure Boot? [Y/N]" secureboot
else
        secureboot="n"
fi
read -p "VM Build? [Y/N] " vm
if echo "$vm" | grep -iqF y; then
        read -p "SSH key url: " sshkeyurl
else
        sshkeyurl=""
fi
read -p "Attack Build? [Y/N] " extra
read -p "Disk Encryption? [Y/N] " encryption
if echo "$encryption" | grep -iqF y; then
        while true; do
                read -sp 'LUKS Encryption Passphrase: ' encpass
		echo
		read -sp 'Confirm LUKS Encryption Passphrase: ' encpass2
		echo
		[ "$encpass" = "$encpass2" ] && break
		echo "Passwords didn't match. Try again."
	done
fi
read -p "Headless Install? [Y/N] " server
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
else
        isstatic="N"
        address=""
        gateway=""
        dns="" 
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

#### Partitioning ####
printf "\n\nPartitioning disk(s)...\n"
umount -f -l /mnt 2>/dev/null
swapoff /dev/mapper/lvgroup-swap 2>/dev/null
vgchange -a n lvgroup 2>/dev/null
cryptsetup close cryptlvm 2>/dev/null
disk=$(sudo fdisk -l | grep "dev" | grep -o -P "(?=/).*(?=:)" | cut -d$'\n' -f1)
echo "label: gpt" | sfdisk --no-reread --force $disk
if echo "$legacyboot" | grep -iqF n; then
        sfdisk --no-reread --force $disk << EOF
        ,260M,U,*
        ;
EOF
else
        sfdisk --no-reread --force $disk << EOF
        ,1M,21686148-6449-6E6F-744E-656564454649,*
        ;
EOF
fi
if echo "$vm" | grep -iqF y; then
        diskpart1=${disk}1
        diskpart2=${disk}2
else
        
	diskpart1=$(sudo fdisk -l | grep "dev" | sed -n "2p" | cut -d " " -f 1)
        diskpart2=$(sudo fdisk -l | grep "dev" | sed -n "3p" | cut -d " " -f 1)
fi

#### LVM on LUKS ####
if echo "$encryption" | grep -iqF y; then
        printf "\n\nEncrpting primary partition...\n"
        echo $encpass | cryptsetup -q luksFormat "${diskpart2}"
        echo $encpass | cryptsetup open "${diskpart2}" cryptlvm -
	printf "\n\nCreating LVM...\n"
        pvcreate -ffy /dev/mapper/cryptlvm
        vgcreate lvgroup /dev/mapper/cryptlvm
else
        printf "\n\nCreating LVM...\n"
        pvcreate -ffy "${diskpart2}"
        vgcreate lvgroup "${diskpart2}"
fi

#### Format /root /swap ####
printf "\n\nConfiguring and formatting LVM...\n"
lvcreate -y -L 4G lvgroup -n swap
lvcreate -y -l 100%FREE lvgroup -n root
mkfs.ext4 -FF /dev/lvgroup/root
mkswap /dev/lvgroup/swap
mount /dev/lvgroup/root /mnt
swapon /dev/lvgroup/swap

#### Format /boot ####
if echo "$legacyboot" | grep -iqF n; then
        mkfs.fat -I -F 32 "${diskpart1}"
fi
mkdir /mnt/boot
mount "${diskpart1}" /mnt/boot

#### Installation ####
printf "\n\nPackstrap packages...\n"

#To avoid issues with default mirrors breaking keys, pre-install archlinux-keyring
pacman --noconfirm -Sy archlinux-keyring

# More packages can be added here
if echo "$server" | grep -iqF y; then
        pacstrap /mnt base linux lvm2 grub efibootmgr
else
	pacstrap /mnt base linux linux-firmware lvm2 grub efibootmgr
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
vm=$vm
isstatic=$isstatic
address=$address
gateway=$gateway
dns=$dns
sshkeyurl=$sshkeyurl
encryption=$encryption
disk=$disk
diskpart2=$diskpart2
secureboot=$secureboot
legacyboot=$legacyboot" > /mnt/nemesis.sh

echo '
#### Time Zone ####
printf "\n\nSetting timezone...\n"
ln -sf /usr/share/zoneinfo/Europe/London /etc/localtime
hwclock --systohc

#### Localization ####
printf "\nConfiguring locale...\n"
echo en_GB.UTF-8 UTF-8 > /etc/locale.gen
locale-gen
echo LANG=en_GB.UTF-8 > /etc/locale.conf
export LANG=en_GB.UTF-8
echo KEYMAP=uk > /etc/vconsole.conf

#### Network Config ####
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
	#rm /etc/resolv.conf && ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
	systemctl enable systemd-networkd
fi
systemctl enable systemd-resolved

#### Pacman Init ####
printf "\n\nInitializing Pacman... \n"
curl https://blackarch.org/strap.sh | sh
echo "Server = http://mirror.zetup.net/blackarch/blackarch/os/x86_64" > /etc/pacman.d/blackarch-mirrorlist
echo "
[multilib]
Include = /etc/pacman.d/mirrorlist" >> /etc/pacman.conf
pacman --noconfirm -Syu 
## intel ##
#pacman --noconfirm -S intel-ucode mesa lib32-mesa vulkan-intel  
## amd ##
#pacman --noconfirm -S amd-ucode mesa lib32-mesa amdvlk lib32-amdvlk
## utils ##
pacman --noconfirm -S base-devel yay neovim openssh git fish toilet lolcat neofetch fortune-mod cowsay lib32-glibc wget socat python python-pip p7zip tmux go cifs-utils tcpdump proxychains-ng openvpn wireguard-tools systemd-resolvconf cmatrix asciiquarium

#### User Setup ####
printf "\n\nSetting up low priv user...\n"
echo "%wheel    ALL=(ALL) ALL" >> /etc/sudoers
useradd -m -G users,wheel $username
echo -e "$password\n$password" | passwd $username
sudo -Hu $username mkdir /home/$username/.ssh
sudo -Hu $username chmod 750 /home/$username/.ssh
chgrp users /opt
chmod 775 /opt
chmod g+s /opt

#### SSH setup ####
printf "\n\nConfiguring SSH... \n"
echo "
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin no
PasswordAuthentication no" >> /etc/ssh/sshd_config
echo -e "#\x21/bin/bash" > /etc/motd.sh && \
echo "echo \"$(toilet -f pagga -w 110 -F border Nemesis | lolcat -ft)\"" >> /etc/motd.sh && \
echo "echo \"\" ; neofetch ; echo \"\" ; fortune | cowsay -f head-in -W 110 | lolcat -f ; echo \"\"" >> /etc/motd.sh && \
chmod +x /etc/motd.sh && \
echo "session    optional   pam_exec.so          stdout /etc/motd.sh" >> /etc/pam.d/system-login
if echo "$vm" | grep -iqF y; then
        systemctl enable sshd
        if [ -n "$sshkeyurl" ]; then
                sudo -Hu $username curl $sshkeyurl > /home/$username/.ssh/authorized_keys
		chmod 600 /home/$username/.ssh/authorized_keys
		chown $username:$username /home/$username/.ssh/authorized_keys
        fi
fi

#### RDP Setup ####
if echo "$server" | grep -iqF n; then
        if echo "$vm" | grep -iqF y; then
                printf "\n\nConfiguring RDP... \n"
                pacman --noconfirm -S sbc
                sudo -Hu $username /bin/sh -c "echo $password | yay --sudoflags \"-S\" --noconfirm -S xrdp xorgxrdp pulseaudio-module-xrdp"
                echo "allowed_users=anybody" > /etc/X11/Xwrapper.config
                sudo -u $username curl https://raw.githubusercontent.com/cinerieus/nemesis/master/xinitrc -o /home/$username/.xinitrc
		echo "- Enable <Show Virtual Devices> in the audio panel, right click -> Configure Audio Volume" >> /home/$username/readme.txt
                curl https://raw.githubusercontent.com/cinerieus/nemesis/master/xrdp.ini -o /etc/xrdp/xrdp.ini
                curl https://raw.githubusercontent.com/cinerieus/nemesis/master/xrdp_logo.bmp -o /usr/share/xrdp/xrdp_logo.bmp
                curl https://raw.githubusercontent.com/cinerieus/nemesis/master/xrdp_bg.bmp -o /usr/share/xrdp/xrdp_bg.bmp
		systemctl enable xrdp
	fi
fi

#### Initramfs ####
printf "n\nSetting up initramfs...\n"
if echo "$encryption" | grep -iqF y; then
        echo "HOOKS=(base udev autodetect keyboard keymap consolefont modconf block encrypt lvm2 filesystems fsck)" > /etc/mkinitcpio.conf
	#echo "MODULES=(vfat)" >> /etc/mkinitcpio.conf
else
        echo "HOOKS=(base udev autodetect keyboard keymap consolefont modconf block lvm2 filesystems fsck)" > /etc/mkinitcpio.conf
fi
mkinitcpio -P

#### Bootloader ####
printf "\n\nConfiguring bootloader...\n"
echo GRUB_DISTRIBUTOR=\"Arch Nemesis\" > /etc/default/grub
if echo "$legacyboot" | grep -iqF n; then
        if echo "$secureboot" | grep -iqF y; then
	        grub-install --removable --target=x86_64-efi --efi-directory=/boot --bootloader-id=GRUB --sbat=/usr/share/grub/sbat.csv --modules="all_video boot btrfs cat chain configfile echo efifwsetup efinet ext2 fat font gettext gfxmenu gfxterm gfxterm_background gzio halt help hfsplus iso9660 jpeg keystatus loadenv loopback linux ls lsefi lsefimmap lsefisystab lssal memdisk minicmd normal ntfs part_apple part_msdos part_gpt password_pbkdf2 png probe reboot regexp search search_fs_uuid search_fs_file search_label sleep smbios test true video xfs zfs zfscrypt zfsinfo play cpuid tpm luks lvm"
		sudo -u $username /bin/sh -c "echo $password | yay --sudoflags \"-S\" --noconfirm -S shim-signed sbsigntools"
		mv /boot/EFI/BOOT/BOOTx64.EFI /boot/EFI/BOOT/grubx64.efi
		cp /usr/share/shim-signed/shimx64.efi /boot/EFI/BOOT/BOOTx64.EFI
		cp /usr/share/shim-signed/mmx64.efi /boot/EFI/BOOT/
		mkdir /opt/sb
		openssl req -newkey rsa:4096 -nodes -keyout /opt/sb/MOK.key -new -x509 -sha256 -days 3650 -subj "/CN=MOK/" -out /opt/sb/MOK.crt
		openssl x509 -outform DER -in /opt/sb/MOK.crt -out /opt/sb/MOK.cer
		sbsign --key /opt/sb/MOK.key --cert /opt/sb/MOK.crt --output /boot/vmlinuz-linux /boot/vmlinuz-linux
		sbsign --key /opt/sb/MOK.key --cert /opt/sb/MOK.crt --output /boot/EFI/BOOT/grubx64.efi /boot/EFI/BOOT/grubx64.efi
		mkdir -p /etc/pacman.d/hooks
		curl https://raw.githubusercontent.com/cinerieus/nemesis/master/999-sign_kernel_for_secureboot.hook -o /etc/pacman.d/hooks/999-sign_kernel_for_secureboot.hook
		cp /opt/sb/MOK.cer /boot
		chown root:root /opt/sb
		chmod -R 600 /opt/sb
		echo "- Remove /boot/EFI/BOOT/mmx64.efi & /boot/MOK.cer" >> /home/$username/readme.txt
	else
	        grub-install --removable --target=x86_64-efi --efi-directory=/boot --bootloader-id=GRUB --sbat /usr/share/grub/sbat.csv
	fi
else
        grub-install --target=i386-pc $disk
fi
if echo "$encryption" | grep -iqF y; then
        cryptdevice=$(blkid ${diskpart2} -s UUID -o value)
        echo GRUB_CMDLINE_LINUX="cryptdevice=UUID=$cryptdevice:cryptlvm" >> /etc/default/grub
fi
grub-mkconfig -o /boot/grub/grub.cfg

#### Customization ####
printf "\n\nCustomizing... \n"
sudo -u $username curl https://raw.githubusercontent.com/cinerieus/nemesis/master/bashrc -o /home/$username/.bashrc
sudo -u $username curl https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim -o /home/$username/.local/share/nvim/site/autoload/plug.vim --create-dirs
sudo -u $username curl https://raw.githubusercontent.com/cinerieus/nemesis/master/init.vim -o /home/$username/.config/nvim/init.vim --create-dirs
sudo -u $username nvim +:PlugInstall +:qa
sudo -u $username curl https://raw.githubusercontent.com/oh-my-fish/oh-my-fish/master/bin/install > /home/$username/install.fish
sudo -u $username fish /home/$username/install.fish --noninteractive && \
mv /home/$username/install.fish /root
sudo -u $username git clone https://github.com/cinerieus/theme-sushi.git /home/$username/.local/share/omf/themes/sushi
sudo -u $username curl https://raw.githubusercontent.com/cinerieus/nemesis/master/config.fish -o /home/$username/.config/fish/config.fish
sudo -u $username fish -c "omf theme sushi"
cp /home/$username/.bashrc /root/.profile
mkdir -p /root/.local/share/nvim/site/autoload && cp /home/$username/.local/share/nvim/site/autoload/plug.vim /root/.local/share/nvim/site/autoload/plug.vim
mkdir -p /root/.config/nvim && cp /home/$username/.config/nvim/init.vim /root/.config/nvim/init.vim
nvim +:PlugInstall +:qa
fish /root/install.fish --noninteractive
rm /root/install.fish
cp -r /home/$username/.local/share/omf/themes/sushi /root/.local/share/omf/themes/
cp -r /home/$username/.config/fish/config.fish /root/.config/fish/config.fish
fish -c "omf theme sushi"
usermod -s /bin/fish $username
usermod -s /bin/fish root
sudo -u $username echo "set -g mouse on" > /home/$username/.tmux.conf
echo "set -g mouse on" > /root/.tmux.conf

## build specific setup ##
if echo "$vm" | grep -iqF y; then
        pacman --noconfirm -S open-vm-tools gtkmm3
	mkdir -p /etc/xdg/autostart
	cp /etc/vmware-tools/vmware-user.desktop /etc/xdg/autostart/vmware-user.desktop
	systemctl enable vmtoolsd
	systemctl enable vmware-vmblock-fuse
fi

if echo "$server" | grep -iqFv y; then
	pacman --noconfirm -S xorg-server plasma-meta plasma-wayland-session kwalletmanager kvantum-qt5 dolphin kwrite kate gwenview konsole spectacle chromium firefox-developer-edition libreoffice remmina
	pacman --noconfirm -S pipewire pipewire-audio pipewire-alsa pipewire-pulse pipewire-jack
	## Temp workaround for sddm-kcm bug
	echo "DisplayServer=x11" >> /etc/sddm.conf
	systemctl enable NetworkManager
	systemctl enable sddm
fi

## attack build - extra tools ##
if echo "$extra" | grep -iqF y; then
	## tools ##
	pacman --noconfirm -S nmap impacket metasploit sqlmap john medusa ffuf nullinux linux-smart-enumeration seclists bloodhound-python ldapdomaindump ntdsxtract binwalk evil-winrm responder freerdp gowitness miniserve cewl strace pspy gittools scoutsuite pacu subfinder httpx dnsx gau nuclei interactsh-client
	## extra ##
	umask 002
	mkdir -p /opt/wordlists /opt/linux /opt/windows /opt/peassng /opt/chisel /opt/c2/ /opt/c2/merlin /opt/c2/sliver
        wget http://downloads.skullsecurity.org/passwords/rockyou.txt.bz2 -O /opt/wordlists/rockyou.bz2
        wget https://github.com/SecWiki/linux-kernel-exploits/archive/refs/heads/master.zip -O /opt/linux/linux-kernel-exploits.zip
        wget https://github.com/ryaagard/CVE-2021-4034/archive/refs/heads/main.zip -O /opt/linux/CVE-2021-4034.zip
        wget https://github.com/andrew-d/static-binaries/archive/refs/heads/master.zip -O /opt/linux/static-binaries.zip
        wget https://github.com/hugsy/gdb-static/archive/refs/heads/master.zip -O /opt/linux/gdb-static.zip
        wget https://github.com/SecWiki/windows-kernel-exploits/archive/refs/heads/master.zip -O /opt/windows/windows-kernel-exploits.zip
        wget https://github.com/interference-security/kali-windows-binaries/archive/refs/heads/master.zip -O /opt/windows/binaries.zip
        wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/archive/refs/heads/master.zip -O /opt/windows/ghostpack_binaries.zip
        wget https://github.com/dirkjanm/krbrelayx/archive/refs/heads/master.zip -O /opt/windows/krbrelayx.zip
        wget https://github.com/carlospolop/PEASS-ng/releases/download/20220925/linpeas.sh -O /opt/peassng/linpeas.sh
        wget https://github.com/carlospolop/PEASS-ng/releases/download/20220925/winPEAS.bat -O /opt/peassng/winPEAS.bat
        wget https://github.com/carlospolop/PEASS-ng/releases/download/20220925/winPEASx64.exe -O /opt/peassng/winPEASx64.exe
        wget https://github.com/carlospolop/PEASS-ng/releases/download/20220925/winPEASx86.exe -O /opt/peassng/winPEASx86.exe
        7z a /opt/peassng/peassng.7z /opt/peassng/* && rm -f /opt/peassng/lin* && rm -f /opt/peassng/win*
        wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz -O /opt/chisel/chisel_1.7.7_linux_amd64.gz
        wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_windows_amd64.gz -O /opt/chisel/chisel_1.7.7_windows_amd64.gz
        wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_windows_386.gz -O /opt/chisel/chisel_1.7.7_windows_386.gz
        wget https://github.com/Ne0nd0g/merlin/releases/download/v1.5.0/merlinServer-Linux-x64.7z -O /opt/c2/merlin/merlinServer-Linux-x64.7z
        wget https://github.com/BishopFox/sliver/releases/download/v1.5.28/sliver-server_linux -O /opt/c2/sliver/sliver-server
        wget https://github.com/BishopFox/sliver/releases/download/v1.5.28/sliver-client_linux -O /opt/c2/sliver/sliver-client
        7z a /opt/c2/sliver/sliver.7z /opt/c2/sliver/* && rm -f /opt/c2/sliver/sliver-*
	echo "
## Todo ##
- Change your password from Ch4ngeM3!

## Fun ##
- cowsay
- fortune
- lolcat
- toilet
- cmatrix 
- asciiquarium
- neofetch

## Tools ##
- nmap
- ncat
- socat
- openvpn
- wireguard
- proxychains
- impacket
- metasploit
- sqlmap
- john-the-ripper
- medusa
- ffuf
- nullinux
- bloodhound-python
- ldapdomaindump
- esedbexport
- ntdsxtract
- binwalk
- evil-winrm
- responder
- freerdp
- gowitness
- miniserve
- cewl
- strace
- pspy
- gittools
- scoutsuite
- pacu
- merlin
- sliver
- chisel
- subfinder
- httpx
- dnsx
- gau
- nuclei
- interactsh-client

## Scripts ##
- linux-smart-enumeration
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
	" >> /home/$username/readme.txt
else
	echo "
## Todo ##
- Change your password from Ch4ngeM3!

## Fun ##
- cowsay
- fortune
- lolcat
- toilet
- cmatrix 
- asciiquarium
- neofetch
	" >> /home/$username/readme.txt
fi

if echo "$server" | grep -iqFv y; then
	## font config ##
	curl https://raw.githubusercontent.com/cinerieus/nemesis/master/local.conf -o /etc/fonts/local.conf
	sudo -Hu $username curl https://raw.githubusercontent.com/cinerieus/nemesis/master/Xresources -o /home/$username/.Xresources && cp /home/$username/.Xresources /root/.Xresources
	sudo -Hu $username xrdb -merge ~/.Xresources && xrdb -merge ~/.Xresources
	ln -s /usr/share/fontconfig/conf.avail/10-sub-pixel-rgb.conf /etc/fonts/conf.d/
	ln -s /usr/share/fontconfig/conf.avail/10-hinting-slight.conf /etc/fonts/conf.d/
	ln -s /usr/share/fontconfig/conf.avail/11-lcdfilter-default.conf /etc/fonts/conf.d/
	echo export FREETYPE_PROPERTIES="truetype:interpreter-version=40" >> /etc/profile.d/freetype2.sh
	sudo -Hu $username fc-cache -fv && fc-cache -fv
	
	## firefox anti-telemetry profile ##
	mkdir -p /home/$username/.mozilla/firefox /root/.mozilla/firefox
	chown -R $username:$username /home/$username/.mozilla
	sudo -Hu $username curl https://raw.githubusercontent.com/cinerieus/nemesis/master/d2rbzfof.dev-edition-default.7z -o /home/$username/.mozilla/firefox/d2rbzfof.dev-edition-default.7z
	sudo -Hu $username 7z x /home/$username/.mozilla/firefox/d2rbzfof.dev-edition-default.7z -o/home/$username/.mozilla/firefox && rm /home/$username/.mozilla/firefox/d2rbzfof.dev-edition-default.7z
	cp -r /home/$username/.mozilla/firefox/d2rbzfof.dev-edition-default /root/.mozilla/firefox
fi
#######################' >> /mnt/nemesis.sh

# Chroot and run
#################
printf "\n\nChrooting and running stage 2..."
chmod +x /mnt/nemesis.sh
arch-chroot /mnt ./nemesis.sh
printf "\n\nCleaning up..."
rm /mnt/nemesis.sh
printf "\n\nDone!"
printf "\n\nRemove install media and reboot."
printf "\n\nRead ~/readme.txt and don't forget to change your password!.\n\n"
sleep 5
#################
