#
# ~/.bashrc
#

# If not running interactively, don't do anything
[[ $- != *i* ]] && return

alias px='proxychains -q'
alias ls='ls --color=auto'
alias ll='ls --color=auto -lah'
alias copy='rsync -ah --info=progress2'
alias cls='clear'
alias solisten='socat file:`tty`,raw,echo=0 tcp-listen:'

PS1='\001\033[01;35m\002[\001\033[01;36m\002\u\001\033[01;35m\002@\001\033[01;36m\002\h \001\033[01;34m\002\W\001\033[01;35m\002]\001\033[00m\002\$ '

export PATH=$PATH:~/.local/bin

umask 002
