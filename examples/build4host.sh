#! /bin/bash

export ROOTDIR=$(cd `dirname $0`; pwd)

export EXTERNAL_PREFIX=/data/openssl
export INSTALL_PREFIX=/data/openssl
export buildDIR=build

export CFLAGS=" \
    -g -O2 \
    -DLINUX \
    -DGRANDSTREAM_NETWORKS \
    -D_GNU_SOURCE \
    -I/data/openssl/include"

export CXXFLAGS="${CFLAGS}"

export CPPFLAGS="${CFLAGS}"

export LDFLAGS=" \
    -L${EXTERNAL_PREFIX}/lib \
    -Wl,-rpath=${EXTERNAL_PREFIX}/lib"

rm -rf ${buildDIR}; mkdir -p ${buildDIR}; cd ${buildDIR}
cmake .. \
    -DCMAKE_INSTALL_PREFIX:PATH=${INSTALL_PREFIX} \
    -DSSL_LIBRARY:FILEPATH=${EXTERNAL_PREFIX}/lib/libssl.so \
    -DCRYPTO_LIBRARY:FILEPATH=${EXTERNAL_PREFIX}/lib/libcrypto.so

make
make install
