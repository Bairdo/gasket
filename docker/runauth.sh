#!/bin/bash

hostapd -ddt /etc/hostapd/wired.conf > /etc/hostapd/hostapd.log 2>&1 &
python3 /faucet-src/faucet/rule_manager.py /etc/ryu/faucet/base-acls.yaml /etc/ryu/faucet/faucet-acls.yaml
ryu-manager faucet.faucet &
echo $! > /etc/ryu/faucet/contr_pid
python3.5 /faucet-src/faucet/auth_app.py --config /etc/ryu/faucet/auth.yaml
