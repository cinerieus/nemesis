call plug#begin('~/.vim/plugged')
"Plug 'drewtempelmeyer/palenight.vim'
Plug 'dracula/vim'
Plug 'itchyny/lightline.vim'
Plug 'frazrepo/vim-rainbow'
call plug#end()

""Look
set background=dark
colorscheme dracula
let g:lightline={ 'colorscheme': 'dracula' }
let $NVIM_TUI_ENABLE_TRUE_COLOR=1
set termguicolors
let g:palenight_terminal_italics=1

""Feel
set number
set mouse:a
"Return to last position in file
if has("autocmd")
  au BufReadPost * if line("'\"") > 0 && line("'\"") <= line("$") | exe "normal! g`\"" | endif
endif

""Syntax and Formatting
syntax enable
filetype plugin indent on
let g:rainbow_active=1
set tabstop=4
set shiftwidth=4
set expandtab
