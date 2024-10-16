#!/usr/bin/env bash

export OPENSSL_VERSION=3.3.0
export OPENSSL_URL=https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz
export OPENSSL_TAR=openssl/$OPENSSL_VERSION/source-tree.tar.gz
export OPENSSL_SOURCE=openssl/$OPENSSL_VERSION/openssl-$OPENSSL_VERSION
# shellcheck disable=SC2155
export OPENSSL_OUTPUT=$(pwd)/openssl/$OPENSSL_VERSION/output/$1

# Get logical CPU count based on the OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    cpu_count=$(nproc --all)
elif [[ "$OSTYPE" == "darwin"* ]]; then
    cpu_count=$(sysctl -n hw.logicalcpu)
else
    echo "Unsupported OS."
    exit 1
fi
export PROC_COUNT=$((cpu_count > 1 ? cpu_count - 1 : 1))

# OpenSSL
echo "OpenSSL $OPENSSL_VERSION ($OPENSSL_URL => $OPENSSL_OUTPUT):"
echo " - Tar File    => '$OPENSSL_TAR'"
echo " - Source File => '$OPENSSL_SOURCE'"
echo " - Target      => '$1'"
echo " - Compiler    => '$2'"
echo " - CPU Count   => $PROC_COUNT"

# Download and unpack OpenSSL archive if needed
if [ ! -f "$OPENSSL_TAR" ]; then
  echo "[*] Download OpenSSL $OPENSSL_VERSION source tree from $OPENSSL_URL"
  mkdir -p openssl/$OPENSSL_VERSION/output
  curl -s -L -o $OPENSSL_TAR $OPENSSL_URL
fi

if [ ! -d "$OPENSSL_SOURCE" ]; then
  echo "[*] Unzip OpenSSL archive $OPENSSL_TAR into $OPENSSL_SOURCE"
  tar -xzf $OPENSSL_TAR -C openssl/$OPENSSL_VERSION
fi

# Configure and build OpenSSL
if [ ! -d "$OPENSSL_OUTPUT" ]; then
  echo "[*] Configure and build OpenSSL"
  mkdir -p "$OPENSSL_OUTPUT"
  cd $OPENSSL_SOURCE || exit
  ./Configure "$1" no-shared --prefix="$OPENSSL_OUTPUT" --cross-compile-prefix="$2"
  echo "[*] Build OpenSSL"
  make -j$PROC_COUNT
  make install_sw
fi