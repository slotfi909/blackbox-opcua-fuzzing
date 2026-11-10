#!/usr/bin/env bash
set -e

pip3 install virtualenv

git clone https://github.com/FreeOpcUa/python-opcua.git
(
  cd python-opcua || exit 1

  virtualenv .env

  .env/bin/pip install .
  .env/bin/pip install cryptography
)

cp targets/python-opcua/target target
