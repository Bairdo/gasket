#!/bin/bash

hostapd -ddt /etc/hostapd/wired.conf > /etc/hostapd/hostapd.log 2>&1 &
echo "Started hostapd"
echo "Using base-no-authed-acls.yaml where no users are authenticated."
cp /etc/ryu/faucet/base-no-authed-acls.yaml /etc/ryu/faucet/base-acls.yaml
python3 /faucet-src/faucet/rule_manager.py /etc/ryu/faucet/base-acls.yaml /etc/ryu/faucet/faucet-acls.yaml
echo "Starting Faucet"
ryu-manager faucet.faucet &
echo $! > /etc/ryu/faucet/contr_pid
echo "Starting auth_app"
python3.5 /faucet-src/faucet/auth_app.py --config /etc/ryu/faucet/auth.yaml
