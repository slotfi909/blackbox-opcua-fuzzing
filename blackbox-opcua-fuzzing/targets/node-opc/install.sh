#!/usr/bin/env bash
set -eo pipefail

apt-get update
apt-get install -y npm

curl -fsSL https://deb.nodesource.com/setup_14.x | bash -
apt-get install -y nodejs

npm install node-opcua --save

NODE_OPCUA_REVISION=bc0fd185f4905cd03c83c7a278365424f2b46bac # v2.47.0
git clone https://github.com/node-opcua/node-opcua
(
  cd node-opcua
  git checkout --detach "$NODE_OPCUA_REVISION" || {
    echo "Cannot check out node-opcua revision $NODE_OPCUA_REVISION" >&2
    exit 1
  }
  git submodule update --init --recursive
)

cp targets/node-opc/target target
