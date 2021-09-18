call plug#begin('~/.vim/plugged')
Plug 'drewtempelmeyer/palenight.vim'
Plug 'itchyny/lightline.vim'
Plug 'frazrepo/vim-rainbow'
call plug#end()

""Look
set background=dark
colorscheme palenight
let g:lightline={ 'colorscheme': 'palenight' }
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
