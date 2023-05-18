#!/bin/bash

# Packages
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y build-essential clang flex bison g++ gawk gcc-multilib g++-multilib musl-tools mingw-w64 gettext libncurses5-dev libssl-dev python3-distutils python3-venv rsync unzip zlib1g-dev file fish neovim tmux git curl wget socat python3 python3-pip p7zip tmux cifs-utils

# Customization
sudo usermod -aG users $USER
sudo usermod -aG users root
sudo chgrp users /opt
sudo chmod 775 /opt
sudo chmod g+s /opt
curl https://raw.githubusercontent.com/cinerieus/nemesis/master/bashrc -o ~/.bashrc
curl https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim -o ~/.local/share/nvim/site/autoload/plug.vim --create-dirs
curl https://raw.githubusercontent.com/cinerieus/nemesis/master/init.vim -o ~/.config/nvim/init.vim --create-dirs
nvim +:PlugInstall +:qa
curl https://raw.githubusercontent.com/oh-my-fish/oh-my-fish/master/bin/install > ~/install.fish
fish ~/install.fish --noninteractive
git clone https://github.com/cinerieus/theme-sushi.git ~/.local/share/omf/themes/sushi
curl https://raw.githubusercontent.com/cinerieus/nemesis/master/config.fish -o ~/.config/fish/config.fish
fish -c "omf theme sushi"
sudo cp ~/.bashrc /root/.profile
sudo mv ~/install.fish /root
sudo fish /root/install.fish --noninteractive
sudo rm /root/install.fish
sudo mkdir -p /root/.local/share/nvim/site/autoload && sudo cp ~/.local/share/nvim/site/autoload/plug.vim /root/.local/share/nvim/site/autoload/plug.vim
sudo mkdir -p /root/.config/nvim && sudo cp ~/.config/nvim/init.vim /root/.config/nvim/init.vim
sudo nvim +:PlugInstall +:qa
sudo cp -r ~/.local/share/omf/themes/sushi /root/.local/share/omf/themes/
sudo cp -r ~/.config/fish/config.fish /root/.config/fish/config.fish
sudo fish -c "omf theme sushi"
sudo usermod -s /bin/fish $USER
sudo usermod -s /bin/fish root
git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
curl https://raw.githubusercontent.com/cinerieus/nemesis/master/tmux.conf -o ~/.tmux.conf
~/.tmux/plugins/tpm/scripts/install_plugins.sh
sudo git clone https://github.com/tmux-plugins/tpm /root/.tmux/plugins/tpm
sudo curl https://raw.githubusercontent.com/cinerieus/nemesis/master/tmux.conf -o /root/.tmux.conf
sudo /root/.tmux/plugins/tpm/scripts/install_plugins.sh
