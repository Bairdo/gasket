#!/bin/bash

nohup ryu-manager ryu.app.ofctl_rest faucet.faucet --wsapi-port 8084 &
echo $! > /etc/ryu/faucet/contr_pid

nohup python3.5 /faucet-src/faucet/HTTPServer.py --config  /faucet-src/tests/config/auth.yaml > httpserver.txt &
echo $! > /root/http_server.pid.txt
