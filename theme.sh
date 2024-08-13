# Get themes
yay --noconfirm -S full-dracula-theme-git konsole-dracula-git dracula-icons-git

# Set Kvantum theme
kvantummanager --set Dracula

# Set global theme
lookandfeeltool -a Dracula

# Set application style
kwriteconfig6 --file kdeglobals --group KDE --key widgetStyle kvantum-dark

# Set icon theme
/usr/lib/plasma-changeicons Dracula

# Download wallpapers
sudo git clone https://github.com/dracula/wallpaper.git /usr/share/wallpapers/dracula

# Set lockscreen bg
kwriteconfig6 --file kscreenlockerrc --group Greeter --group Wallpaper --group org.kde.image --group General --key Image "file:///usr/share/wallpapers/dracula/first-collection/arch.png"

# Set desktop bg
qdbus org.kde.plasmashell /PlasmaShell org.kde.PlasmaShell.evaluateScript 'var allDesktops = desktops();print (allDesktops);for (i=0;i<allDesktops.length;i++) {d = allDesktops[i];d.wallpaperPlugin = "org.kde.image";d.currentConfigGroup = Array("Wallpaper", "org.kde.image", "General");d.writeConfig("Image", "file:///usr/share/wallpapers/dracula/first-collection/arch.png")}'

# Set SDDM theme
sudo mkdir /etc/sddm.conf.d
echo "[Autologin]
Relogin=false
Session=
User=

[General]
HaltCommand=/usr/bin/systemctl poweroff
RebootCommand=/usr/bin/systemctl reboot

[Theme]
Current=Dracula
CursorTheme=Dracula-cursors
Font=Noto Sans,10,-1,0,50,0,0,0,0,0

[Users]
MaximumUid=60513
MinimumUid=1000" | sudo tee /etc/sddm.conf.d/kde_settings.conf

# Restart plasma
plasmashell --replace &>/dev/null &
disown

cat << EOM
Manual Steps:
- Application Style GTK Theme
- Application launcher icon
- Konsole Profile
- KWrite
EOM
