#!/bin/sh

_int(){
    echo "Caught $? signal!"
    kill -s INT "$gasket"
    wait "$gasket"
}

trap _int INT EXIT QUIT

echo "Using base-no-authed-acls.yaml where no users are authenticated."
cp /etc/faucet/gasket/base-no-authed-acls.yaml /etc/faucet/gasket/base-acls.yaml
python3 /gasket-src/gasket/rule_manager.py /etc/faucet/gasket/base-acls.yaml /etc/faucet/faucet-acls.yaml
echo "Starting Gasket"
python3 -m gasket.auth_app /etc/faucet/gasket/auth.yaml &
gasket=$!
echo "waiting for Gasket pid: $gasket"
wait "$gasket"
