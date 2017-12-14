#!/bin/bash

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

# Modified by Roberto
source /home/rocordoni/Documents/2017-1_TCC/tutorials/env.sh

CLI_PATH=$BMV2_PATH/targets/simple_switch/sswitch_CLI

echo "resetting registers"
echo "register_reset ntp_monlist_request_bytes_counter" | $CLI_PATH build/p4src/alg-1.2.p4.json
echo "register_reset ntp_monlist_response_bytes_counter" | $CLI_PATH build/p4src/alg-1.2.p4.json
echo "register_reset ntp_counter" | $CLI_PATH build/p4src/alg-1.2.p4.json
echo "register_reset amplification_attack" | $CLI_PATH build/p4src/alg-1.2.p4.json
echo "register_reset amplification_attack_timestamp" | $CLI_PATH build/p4src/alg-1.2.p4.json
echo

