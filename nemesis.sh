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
read -p "VM Build? [Y/N] " vm
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
else
        isstatic="N"
        address=""
        gateway=""
        dns=""
        sshkeyurl=""
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
mkfs.ext4 -F $disk
wipefs -af $disk
echo "label: gpt" | sfdisk --force $disk
sfdisk --force $disk << EOF
,260M,U,*
;
EOF

if echo "$vm" | grep -iqF y; then
        diskpart1=${disk}1
        diskpart2=${disk}2
else
        
	diskpart1=$(sudo fdisk -l | grep "dev" | sed -n "2p" | cut -d " " -f 1)
        diskpart2=$(sudo fdisk -l | grep "dev" | sed -n "3p" | cut -d " " -f 1)
fi

#### Encryption ####
if echo "$encryption" | grep -iqF y; then
        printf "\n\nEncrpting primary partition...\n"
        read -sp 'LUKS Encryption Passphrase: ' encpass
        echo $encpass | cryptsetup -q luksFormat "${diskpart2}"
        echo $encpass | cryptsetup open "${diskpart2}" cryptlvm -
        pvcreate /dev/mapper/cryptlvm
        vgcreate lvgroup /dev/mapper/cryptlvm
else
        pvcreate "${diskpart2}"
        vgcreate lvgroup "${diskpart2}"
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
mkfs.fat -F 32 "${diskpart1}"
mkdir /mnt/boot
mount "${diskpart1}" /mnt/boot

#### Installation ####
printf "\n\nPackstrap packages...\n"
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
diskpart2=$diskpart2" > /mnt/nemesis.sh

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
	rm /etc/resolv.conf && ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
	systemctl enable systemd-networkd
fi
systemctl enable systemd-resolved

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
        cryptdevice=$(lsblk -dno UUID ${diskpart2})
        echo GRUB_CMDLINE_LINUX="cryptdevice=UUID=$cryptdevice:cryptlvm" > /etc/default/grub
fi
grub-mkconfig -o /boot/grub/grub.cfg

#### Pacman Init ####
printf "\n\nInitializing Pacman... \n"
curl https://blackarch.org/strap.sh | sh
echo "Server = http://mirror.zetup.net/blackarch/blackarch/os/x86_64" > /etc/pacman.d/blackarch-mirrorlist
echo "
[multilib]
Include = /etc/pacman.d/mirrorlist" >> /etc/pacman.conf
pacman --noconfirm -Syu 
pacman --noconfirm -S sudo which neovim openssh git fish toilet lolcat neofetch fortune-mod cowsay

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
if echo "$server" | grep -iqF y; then
        systemctl enable sshd
        if [ -n "$sshkeyurl" ]; then
                echo "
                HostKey /etc/ssh/ssh_host_ed25519_key
                PermitRootLogin no
                PasswordAuthentication no" >> /etc/ssh/sshd_config
		echo -e "#\x21/bin/bash" > /etc/motd.sh && \
                echo "echo \"$(toilet -f pagga -w 110 -F border Nemesis | lolcat -ft)\"" >> /etc/motd.sh && \
                echo "echo \"\" ; neofetch ; echo \"\" ; fortune | cowsay -f head-in -W 110 | lolcat -f ; echo \"\"" >> /etc/motd.sh && \
                chmod +x /etc/motd.sh && \
                echo "session    optional   pam_exec.so          stdout /etc/motd.sh" >> /etc/pam.d/system-login
                sudo -Hu $username curl $sshkeyurl > /home/$username/.ssh/authorized_keys
		sudo -Hu $username chmod 600 /home/$username/.ssh/authorized_keys
        else
                echo "
                HostKey /etc/ssh/ssh_host_ed25519_key
                PermitRootLogin no" >> /etc/ssh/sshd_config
        fi
fi

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

## build specific setup ##
if echo "$vm" | grep -iqF y; then
        pacman --noconfirm -S open-vm-tools gtkmm3
	mkdir -p /etc/xdg/autostart
	cp /etc/vmware-tools/vmware-user.desktop /etc/xdg/autostart/vmware-user.desktop
	systemctl enable vmtoolsd
	systemctl enable vmware-vmblock-fuse
fi

if echo "$server" | grep -iqFv y; then
	pacman --noconfirm -S alsa-utils xorg-server plasma-meta plasma-wayland-session kwalletmanager kvantum-qt5 dolphin kwrite kate gwenview konsole spectacle chromium firefox-developer-edition libreoffice
	pacman --noconfirm -S pipewire pipewire-alsa pipewire-pulse pipewire-jack
	systemctl enable NetworkManager
	systemctl enable sddm
fi

## intel ##
#pacman --noconfirm -S intel-ucode mesa lib32-mesa vulkan-intel  
## amd ##
#pacman --noconfirm -S amd-ucode mesa lib32-mesa amdvlk lib32-amdvlk
## utils ##
pacman --noconfirm -S base-devel lib32-glibc wget yay socat python python-pip p7zip tmux go cifs-utils tcpdump proxychains-ng openvpn wireguard-tools systemd-resolvconf cmatrix asciiquarium

## attack build - extra tools ##
if echo "$extra" | grep -iqF y; then
	## tools ##
	pacman --noconfirm -S nmap impacket metasploit sqlmap john medusa ffuf nullinux linux-smart-enumeration seclists bloodhound-python ldapdomaindump ntdsxtract binwalk evil-winrm responder freerdp gowitness miniserve cewl strace pspy gittools scoutsuite pacu subfinder httpx dnsx gau nuclei interactsh-client
	## extra ##
	umask 002
	mkdir -p /opt/wordlists /opt/linux /opt/windows /opt/peassng /opt/chisel /opt/c2/
        curl http://downloads.skullsecurity.org/passwords/rockyou.txt.bz2 -o /opt/wordlists/rockyou.bz2
        curl https://github.com/SecWiki/linux-kernel-exploits/archive/refs/heads/master.zip -o /opt/linux/linux-kernel-exploits.zip
        curl https://github.com/ryaagard/CVE-2021-4034/archive/refs/heads/main.zip -o /opt/linux/CVE-2021-4034.zip
        curl https://github.com/andrew-d/static-binaries/archive/refs/heads/master.zip -o /opt/linux/static-binaries.zip
        curl https://github.com/hugsy/gdb-static/archive/refs/heads/master.zip -o /opt/linux/gdb-static.zip
        curl https://github.com/SecWiki/windows-kernel-exploits/archive/refs/heads/master.zip -o /opt/windows/windows-kernel-exploits.zip
        curl https://github.com/interference-security/kali-windows-binaries/archive/refs/heads/master.zip -o /opt/windows/binaries.zip
        curl https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/archive/refs/heads/master.zip -o /opt/windows/ghostpack_binaries.zip
        curl https://github.com/dirkjanm/krbrelayx/archive/refs/heads/master.zip -o /opt/windows/krbrelayx.zip
        curl https://github.com/carlospolop/PEASS-ng/releases/download/20220925/linpeas.sh -o /opt/peassng/linpeas.sh
        curl https://github.com/carlospolop/PEASS-ng/releases/download/20220925/winPEAS.bat -o /opt/peassng/winPEAS.bat
        curl https://github.com/carlospolop/PEASS-ng/releases/download/20220925/winPEASx64.exe -o /opt/peassng/winPEASx64.exe
        curl https://github.com/carlospolop/PEASS-ng/releases/download/20220925/winPEASx86.exe -o /opt/peassng/winPEASx86.exe
        7z a /opt/peassng/peassng.7z /opt/peassng/* && rm -f /opt/peassng/lin* && rm -f /opt/peassng/win*
        curl https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz -o /opt/chisel/chisel_1.7.7_linux_amd64.gz
        curl https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_windows_amd64.gz -o /opt/chisel/chisel_1.7.7_windows_amd64.gz
        curl https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_windows_386.gz -o /opt/chisel/chisel_1.7.7_windows_386.gz
        curl https://github.com/Ne0nd0g/merlin/releases/download/v1.5.0/merlinServer-Linux-x64.7z -o /opt/c2/merlin/merlinServer-Linux-x64.7z --create-dirs
        curl https://github.com/BishopFox/sliver/releases/download/v1.5.28/sliver-server_linux -o /opt/c2/sliver/sliver-server --create-dirs
        curl https://github.com/BishopFox/sliver/releases/download/v1.5.28/sliver-client_linux -o /opt/c2/sliver/sliver-client
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
	" > /home/$username/readme.txt
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
	" > /home/$username/readme.txt
fi

## secure boot script ##
if echo "$encryption" | grep -iqF y; then
	sudo -Hu $username curl https://raw.githubusercontent.com/cinerieus/nemesis/master/secure_boot.sh -o /home/$username/secure_boot.sh
	chmod +x /home/$username/secure_boot.sh
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
#printf "\n\nCleaning up..."
#rm /mnt/nemesis.sh
printf "\n\nDone!"
printf "\n\nRemove install media and reboot."
printf "\n\nRead ~/readme.txt and don't forget to change your password!.\n\n"
#sleep 5
#################
