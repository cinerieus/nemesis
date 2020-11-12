set nocompatible
filetype off
set rtp+=~/.vim/bundle/Vundle.vim
call vundle#begin()
Plugin 'VundleVim/Vundle.vim'
Plugin 'drewtempelmeyer/palenight.vim'
Plugin 'itchyny/lightline.vim'
Plugin 'dense-analysis/ale'
call vundle#end()
filetype plugin indent on

let g:lightline = {
        \ 'colorscheme': 'palenight',
        \ }

syntax on
colorscheme palenight
set laststatus=2
set mouse:a
set number
if has("autocmd")
  au BufReadPost * if line("'\"") > 0 && line("'\"") <= line("$") | exe "normal! g`\"" | endif
endif
