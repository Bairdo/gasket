#!/bin/sh

_int(){
    echo "Caught $? signal!"
    kill -SIGINT "$gasket"
    kill -SIGTERM "$faucet"
    wait "$faucet"
    wait "$gasket"
}

trap _int INT EXIT QUIT

echo "Using base-no-authed-acls.yaml where no users are authenticated."
cp /etc/ryu/faucet/gasket/base-no-authed-acls.yaml /etc/ryu/faucet/gasket/base-acls.yaml
python3 /gasket-src/gasket/rule_manager.py /etc/ryu/faucet/gasket/base-acls.yaml /etc/ryu/faucet/faucet-acls.yaml
echo "Starting Faucet and Gasket"
ryu-manager --pid-file=/var/run/faucet.pid --ofp-tcp-listen-port 6653 faucet.faucet &
faucet=$!
ryu-manager --pid-file=/var/run/gasket.pid --ofp-tcp-listen-port 6663 gasket.auth_app &
gasket=$!
echo "waiting for Gasket pid: $gasket"
wait "$gasket"
