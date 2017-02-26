#!/bin/bash
export FAUCET_CONFIG=/home/ubuntu/faucet-dev/faucet.yaml
export GAUGE_CONFIG=/etc/ryu/faucet/gauge.yaml
export FAUCET_LOG=/var/log/faucet/faucet.log
export FAUCET_EXCEPTION_LOG=/var/log/faucet/faucet_exception.log
export GAUGE_LOG=/var/log/faucet/gauge_exception.log
export GAUGE_EXCEPTION_LOG=/var/log/faucet/gauge_exception.log
export GAUGE_DB_CONFIG=/etc/ryu/faucet/gauge_db.yaml

ryu-manager --verbose src/ryu_faucet/org/onfsdn/faucet/faucet.py
