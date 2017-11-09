#!/bin/bash

hostapd -ddt /etc/hostapd/wired.conf > /etc/hostapd/hostapd.log 2>&1 &
echo "Started hostapd"
echo "Using base-no-authed-acls.yaml where no users are authenticated."
cp /etc/ryu/faucet/base-no-authed-acls.yaml /etc/ryu/faucet/gasket/base-acls.yaml
python3 /gasket-src/gasket/rule_manager.py /etc/ryu/faucet/gasket/base-acls.yaml /etc/ryu/faucet/faucet-acls.yaml
echo "Starting Faucet"
ryu-manager --pid-file=/var/run/faucet.pid faucet.faucet &
echo "Starting auth_app"
python3.5 /gasket-src/gasket/auth_app.py --config /etc/ryu/faucet/gasket/auth.yaml
