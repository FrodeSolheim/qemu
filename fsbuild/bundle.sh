#!/bin/sh

set -e

. fsbuild/plugin.pre.sh

mkdir -p $PLUGIN_BINDIR
cp qemu-uae$SYSTEM_DLL $PLUGIN_BINDIR

mkdir -p $PLUGIN_READMEDIR
cp README.md $PLUGIN_READMEDIR/ReadMe.txt

mkdir -p $PLUGIN_LICENSESDIR
cp LICENSE $PLUGIN_LICENSESDIR/QEMU.txt

if [ $SYSTEM_OS = "macOS" ]; then
cp $PLUGIN_BINDIR/qemu-uae.so $PLUGIN_BINDIR/qemu-uae.dylib
fi

. fsbuild/plugin.post.sh
