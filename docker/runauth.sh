#!/bin/bash
echo "Using base-no-authed-acls.yaml where no users are authenticated."
cp /etc/ryu/faucet/gasket/base-no-authed-acls.yaml /etc/ryu/faucet/gasket/base-acls.yaml
python3 /gasket-src/gasket/rule_manager.py /etc/ryu/faucet/gasket/base-acls.yaml /etc/ryu/faucet/faucet-acls.yaml
echo "Starting Faucet and Gasket"
ryu-manager --pid-file=/var/run/faucet.pid faucet.faucet gasket.auth_app
