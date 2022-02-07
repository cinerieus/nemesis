# Optionally add secure boot to prevent against evil maid attacks on FDE.

mkdir /opt/secure_boot
cd /opt/secure_boot

yay --noconfirm -S shim-signed sbsigntools
sudo cp /usr/share/shim-signed/shimx64.efi /boot/EFI/GRUB/
sudo cp /usr/share/shim-signed/mmx64.efi /boot/EFI/GRUB/
sudo efibootmgr --verbose --disk $(sudo fdisk -l | grep "dev" | grep -o -P "(?=/).*(?=:)" | cut -d$'\n' -f1) --part 1 --create --label "Shim" --loader /EFI/GRUB/shimx64.efi

sudo openssl req -newkey rsa:4096 -nodes -keyout MOK.key -new -x509 -sha256 -days 3650 -subj "/CN=my Machine Owner Key/" -out MOK.crt
sudo openssl x509 -outform DER -in MOK.crt -out MOK.cer
sudo sbsign --key MOK.key --cert MOK.crt --output /boot/vmlinuz-linux /boot/vmlinuz-linux
sudo sbsign --key MOK.key --cert MOK.crt --output /boot/EFI/GRUB/grubx64.efi /boot/EFI/GRUB/grubx64.efi

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

sudo cp MOK.cer /boot/

sudo grub-install --target=x86_64-efi --efi-directory=/boot --bootloader-id=GRUB --modules="tpm" --sbat /usr/share/grub/sbat.csv
sudo sbsign --key MOK.key --cert MOK.crt --output /boot/EFI/GRUB/grubx64.efi /boot/EFI/GRUB/grubx64.efi

cd ~
sudo chown root:root /opt/secure_boot 
sudo chmod -R 600 /opt/secure_boot

echo "Reboot and boot to 'Shim', add MOK.cer to trusted certs in mokmanager."
echo "Don't forget to remove /boot/EFI/GRUB/mmx64.efi"
