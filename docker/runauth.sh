#!/bin/sh

_int(){
    echo "Caught $? signal!"
    kill -SIGINT "$gasket"
    wait "$gasket"
}

trap _int INT EXIT QUIT

echo "Using base-no-authed-acls.yaml where no users are authenticated."
cp /etc/ryu/faucet/gasket/base-no-authed-acls.yaml /etc/ryu/faucet/gasket/base-acls.yaml
python3 /gasket-src/gasket/rule_manager.py /etc/ryu/faucet/gasket/base-acls.yaml /etc/ryu/faucet/faucet-acls.yaml
echo "Starting Gasket"
python3 -m gasket.auth_app /etc/ryu/faucet/gasket/auth.yaml &
gasket=$!
echo "waiting for Gasket pid: $gasket"
wait "$gasket"
