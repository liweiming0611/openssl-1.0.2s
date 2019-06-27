#! /bin/bash

export ROOTDIR=$(cd `dirname $0`; pwd)

export INSTALLPREFIX=/data/openssl

export CFLAGS=" \
    -g \
    -DLINUX \
    -Wno-implicit-function-declaration \
    -DGRANDSTREAM_NETWORKS \
    -I/opt/openssl/include"

export CXXFLAGS="${CFLAGS}"

export CPPFLAGS="${CFLAGS}"

export LDFLAGS=" \
    -L/opt/openssl/lib \
    -Wl,-rpath=/opt/openssl/lib"

if [ -e "Makefile" ]; then
    make clean
    #rm ./Makefile -f
fi

./Configure \
    linux-x86_64 -g3 \
    -Wno-implicit-function-declaration \
    -DGRANDSTREAM_NETWORKS \
    --prefix=${INSTALLPREFIX} \
    --openssldir=/etc/ssl \
    shared \
    threads \
    zlib
