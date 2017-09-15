#!/bin/bash

cd /root/hostapd-2.6/hostapd 
cp /etc/hostapd/hostapd.config .config
make && make install
hostapd -dd /etc/hostapd/wired.conf > /etc/hostapd/hostapd.log 2>&1 &
#freeradius -X > /var/log/ryu/faucet/freerad.log 2>&1 &
python3 /faucet-src/faucet/rule_manager.py /etc/ryu/faucet/base-acls.yaml /etc/ryu/faucet/faucet-acls.yaml
ryu-manager faucet.faucet &
echo $! > /etc/ryu/faucet/contr_pid
python3.5 /faucet-src/faucet/auth_app.py --config /etc/ryu/faucet/auth.yaml
