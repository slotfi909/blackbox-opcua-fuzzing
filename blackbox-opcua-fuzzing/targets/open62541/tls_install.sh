#!/usr/bin/env bash
set -e

# For mbedTLS instead of openssl replace apt install and cmake parameters
# apt:    libmbedtls-dev
# cmake:  -DUA_ENABLE_ENCRYPTION_MBEDTLS=ON

apt-get update
apt-get install -y build-essential cmake libssl-dev

OPEN62541_REVISION=4eec281656aa7aeafbfe3722db17fadb9eacc663
git clone https://github.com/open62541/open62541.git
(
  cd open62541 || exit 1

  git checkout --detach "$OPEN62541_REVISION" || {
    echo "Cannot check out open62541 revision $OPEN62541_REVISION" >&2
    exit 1
  }
  git submodule update --init --recursive
)

mkdir -p target_build
(
  cd target_build || exit 1

  cmake -DBUILD_SHARED_LIBS=ON -DUA_BUILD_EXAMPLES=ON -DUA_ENABLE_ENCRYPTION_OPENSSL=ON ../open62541

  make -j1

  make install
)

cp target_build/bin/examples/server_ctt target
