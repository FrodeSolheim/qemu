#!/bin/sh

set -e

. fsbuild/system.sh

cp VERSION.qemu VERSION
if [ $SYSTEM_OS = "Windows" ]; then
./configure --with-system-pixman --python=python2 --static
else
./configure --with-system-pixman --python=python2
fi
rm VERSION
