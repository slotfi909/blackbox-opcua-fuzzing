#!/usr/bin/env bash
set -e

apt-get update && apt-get install -y openjdk-8-jre wget unzip

wget https://github.com/digitalpetri/opc-ua-demo-server/releases/download/v0.2/milo-demo-server-linux.zip
unzip milo-demo-server-linux.zip
status=0
timeout 5 milo-demo-server/bin/milo-demo-server || status=$?
if [ "$status" -ne 0 ] && [ "$status" -ne 124 ]; then
  echo "Demo server initialization failed with status $status" >&2
  exit "$status"
fi
if [ ! -f /root/.config/milodemoserver/server.json ]; then
  echo "Demo server did not generate server.json" >&2
  exit 1
fi
sed -i 's/62541/4840/g' /root/.config/milodemoserver/server.json
sed -i 's/localhost:4840\//localhost:4840\/milo/g' /opt/app/parse/packet.py

ln -s /opt/app/milo-demo-server/bin/milo-demo-server /opt/app/target
