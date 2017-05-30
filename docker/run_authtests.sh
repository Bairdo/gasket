#!/bin/bash
echo "================= Starting OVS =================="
service openvswitch-switch start

cd /faucet-src/tests

echo "=========== Running faucet unit tests ==========="
time ./faucet_dotcap_integration.py FaucetIntegrationDot1XLogoffTest FaucetIntegrationDot1XLogonTest FaucetIntegrationNoLogOnTest
echo "========== Running faucet config tests =========="
./test_config.py
