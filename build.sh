#!/bin/bash
#
#musl-gcc -static -o exp exp.c
make

if [[ -d ../cpio_files ]]; then
    cp exp ../cpio_files/home/ctf
fi
