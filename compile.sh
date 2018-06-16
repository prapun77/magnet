#!/bin/sh
#-------------------------------------------------------------------------------------------
# This script will compile / strip magnetd.
#-------------------------------------------------------------------------------------------

chmod 755 src/leveldb/build_detect_platform
chmod 755 src/secp256k1/autogen.sh

# Step 1. Level db

cd src/leveldb
make libleveldb.a libmemenv.a

# Step 2. magnet daemon
cd ..
make -f makefile.unix
strip magnetd
magnetd stop
~/magnetd stop

sleep 3
pkill -2 magnetd

sudo rm -rf /usr/bin/magnetd
cp magnetd /usr/bin/
