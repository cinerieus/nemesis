# Nemesis fish configuration

# Disable greeting
set -g fish_greeting ""

# Environment
set -gx EDITOR nvim
set -gx VISUAL nvim
set -gx PAGER less
set -gx LANG en_GB.UTF-8

# PATH additions
fish_add_path /opt/workspace/tools/bin
fish_add_path ~/.local/bin
fish_add_path ~/.cargo/bin

# Aliases
alias vim='nvim'
alias vi='nvim'
alias ll='ls -lah --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias grep='grep --color=auto'
alias ip='ip -color=auto'
alias df='df -h'
alias du='du -h'
alias free='free -h'
alias cat='bat --paging=never 2>/dev/null; or command cat'

# Git aliases
alias gs='git status'
alias ga='git add'
alias gc='git commit'
alias gp='git push'
alias gl='git log --oneline --graph'
alias gd='git diff'

# Security tool aliases
alias serve='python -m http.server 8080'
alias myip='dig +short myip.opendns.com @resolver1.opendns.com'

# Workspace shortcut
alias ws='cd /opt/workspace'

# Initialize starship prompt
if command -q starship
    starship init fish | source
end
