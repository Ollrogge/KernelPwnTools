#!/bin/bash

pushd ../cpio_files
find . -print0 | cpio --null -ov --format=newc | gzip -9 >../rootfs.cpio.gz
popd
