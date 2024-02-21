#!/bin/bash
username=$USERNAME
password=$PASSWORD
sshkeyurl=$SSHKEYURL

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

#### Pacman Init ####
printf "\n\nInitializing Pacman... \n"
curl https://blackarch.org/strap.sh | sh
echo "Server = http://mirror.zetup.net/blackarch/blackarch/os/x86_64" > /etc/pacman.d/blackarch-mirrorlist
#echo "
#[multilib]
#Include = /etc/pacman.d/mirrorlist" >> /etc/pacman.conf
pacman --noconfirm -Syu 
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
AuthorizedKeysFile      .ssh/authorized_keys
KbdInteractiveAuthentication no
UsePAM yes
PrintMotd no
Subsystem       sftp    /usr/lib/ssh/sftp-server
HostKey /etc/ssh/ssh_host_ed25519_key
PasswordAuthentication no" > /etc/ssh/sshd_config
echo -e "#\x21/bin/bash" > /etc/motd.sh && \
echo "echo \"$(toilet -f pagga -w 110 -F border Nemesis | lolcat -ft)\"" >> /etc/motd.sh && \
echo "echo \"\" ; neofetch ; echo \"\" ; fortune | cowsay -f head-in -W 110 | lolcat -f ; echo \"\"" >> /etc/motd.sh && \
chmod +x /etc/motd.sh && \
echo "session    optional   pam_exec.so          stdout /etc/motd.sh" >> /etc/pam.d/system-login
if [ -n "$sshkeyurl" ]; then
  sudo -Hu $username curl $sshkeyurl > /home/$username/.ssh/authorized_keys
  chmod 600 /home/$username/.ssh/authorized_keys
  chown $username:$username /home/$username/.ssh/authorized_keys
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
sudo -u $username git clone https://github.com/tmux-plugins/tpm /home/$username/.tmux/plugins/tpm
sudo -u $username curl https://raw.githubusercontent.com/cinerieus/nemesis/master/tmux.conf -o /home/$username/.tmux.conf
sudo -u $username /home/$username/.tmux/plugins/tpm/scripts/install_plugins.sh
git clone https://github.com/tmux-plugins/tpm /root/.tmux/plugins/tpm
curl https://raw.githubusercontent.com/cinerieus/nemesis/master/tmux.conf -o /root/.tmux.conf
/root/.tmux/plugins/tpm/scripts/install_plugins.sh

## build specific setup ##
pacman --noconfirm -S open-vm-tools gtkmm3
mkdir -p /etc/xdg/autostart
cp /etc/vmware-tools/vmware-user.desktop /etc/xdg/autostart/vmware-user.desktop
systemctl enable vmtoolsd
systemctl enable vmware-vmblock-fuse

## tools ##
pip uninstall -y six markupsafe jinja2 pyyaml netifaces urllib3 idna requests certifi
pacman --noconfirm -S nmap masscan impacket metasploit sqlmap john medusa ffuf enum4linux-ng linux-smart-enumeration seclists bloodhound-python ldapdomaindump ntdsxtract binwalk evil-winrm responder certipy freerdp gowitness miniserve cewl strace pspy gittools scoutsuite pacu subfinder httpx dnsx gau nuclei interactsh-client asnmap
#pip install coercer

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
wget https://github.com/carlospolop/PEASS-ng/releases/download/20240221-e5eff12e/linpeas.sh -O /opt/peassng/linpeas.sh
wget https://github.com/carlospolop/PEASS-ng/releases/download/20240221-e5eff12e/winPEAS.bat -O /opt/peassng/winPEAS.bat
wget https://github.com/carlospolop/PEASS-ng/releases/download/20240221-e5eff12e/winPEASx64.exe -O /opt/peassng/winPEASx64.exe
wget https://github.com/carlospolop/PEASS-ng/releases/download/20240221-e5eff12e/winPEASx86.exe -O /opt/peassng/winPEASx86.exe
7z a /opt/peassng/peassng.7z /opt/peassng/* && rm -f /opt/peassng/lin* && rm -f /opt/peassng/win*
wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz -O /opt/chisel/chisel_1.9.1_linux_amd64.gz
wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_amd64.gz -O /opt/chisel/chisel_1.9.1_windows_amd64.gz
wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_386.gz -O /opt/chisel/chisel_1.9.1_windows_386.gz
wget https://github.com/Ne0nd0g/merlin/releases/download/v2.1.1/merlinServer-Linux-x64.7z -O /opt/c2/merlin/merlinServer-Linux-x64.7z
wget https://github.com/BishopFox/sliver/releases/download/v1.5.41/sliver-server_linux -O /opt/c2/sliver/sliver-server
wget https://github.com/BishopFox/sliver/releases/download/v1.5.41/sliver-client_linux -O /opt/c2/sliver/sliver-client
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
