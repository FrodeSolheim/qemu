#!/bin/sh -e
echo "Bootstrapping qemu-uae..."
git submodule update --init dtc
git submodule update --init pixman
echo "Bootstrap done, you can now run ./configure"
