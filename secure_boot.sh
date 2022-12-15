#!/bin/bash
# Optionally add secure boot to prevent against evil maid attacks on FDE.

mkdir /opt/sb
cd /opt/sb

sudo grub-install --removable --target=x86_64-efi --efi-directory=/boot --bootloader-id=GRUB --sbat=/usr/share/grub/sbat.csv --modules="all_video boot cat chain configfile echo efifwsetup efinet fat font gettext gfxmenu gfxterm gfxterm_background gzio halt help iso9660 jpeg keystatus loadenv loopback linux ls lsefi lsefimmap lsefisystab lssal minicmd normal part_gpt password_pbkdf2 png probe reboot regexp search search_fs_uuid search_fs_file search_label sleep smbios test true video play cpuid tpm luks lvm"

yay --noconfirm -S shim-signed sbsigntools
sudo mv /boot/EFI/BOOT/BOOTx64.EFI /boot/EFI/BOOT/grubx64.efi
sudo cp /usr/share/shim-signed/shimx64.efi /boot/EFI/BOOT/BOOTx64.EFI
sudo cp /usr/share/shim-signed/mmx64.efi /boot/EFI/BOOT/
#sudo efibootmgr -c --disk $(sudo fdisk -l | grep "dev" | grep -o -P "(?=/).*(?=:)" | cut -d$'\n' -f1) --part 1 --loader /boot/EFI/BOOT/BOOTx64.EFI --label "Shim" --unicode
sudo openssl req -newkey rsa:4096 -nodes -keyout /opt/sb/MOK.key -new -x509 -sha256 -days 3650 -subj "/CN=MOK/" -out /opt/sb/MOK.crt
sudo openssl x509 -outform DER -in /opt/sb/MOK.crt -out /opt/sb/MOK.cer
sudo sbsign --key /opt/sb/MOK.key --cert /opt/sb/MOK.crt --output /boot/vmlinuz-linux /boot/vmlinuz-linux
sudo sbsign --key /opt/sb/MOK.key --cert /opt/sb/MOK.crt --output /boot/EFI/BOOT/grubx64.efi /boot/EFI/BOOT/grubx64.efi
sudo cp /opt/sb/MOK.cer /boot

echo "
[Trigger]
Operation = Install
Operation = Upgrade
Type = Package
Target = linux
Target = linux-lts
Target = linux-hardened
Target = linux-zen

[Action]
Description = Signing kernel with Machine Owner Key for Secure Boot
When = PostTransaction
Exec = /usr/bin/find /boot/ -maxdepth 1 -name 'vmlinuz-*' -exec /usr/bin/sh -c 'if ! /usr/bin/sbverify --list {} 2>/dev/null | /usr/bin/grep -q \"signature certificates\"; then /usr/bin/sbsign --key /opt/secure_boot/MOK.key --cert /opt/secure_boot/MOK.crt --output {} {}; fi' ;
Depends = sbsigntools
Depends = findutils
Depends = grep" | sudo tee /etc/pacman.d/hooks/999-sign_kernel_for_secureboot.hook

cd ~
sudo chown root:root /opt/sb
sudo chmod -R 600 /opt/sb

echo "Reboot and boot to 'Shim', add MOK.cer to trusted certs in mokmanager."
echo "Don't forget to remove /boot/EFI/BOOT/mmx64.efi"
