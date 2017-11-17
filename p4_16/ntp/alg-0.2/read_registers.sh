#!/bin/bash

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

# Modified by Roberto
source /home/rocordoni/Documents/2017-1_TCC/tutorials/env.sh

CLI_PATH=$BMV2_PATH/targets/simple_switch/sswitch_CLI
echo "displaying registers"
echo "register_read amplification_attack 0" | $CLI_PATH build/p4src/alg-0.2.p4.json | grep amplification_attack
echo "register_read ntp_counter 0" | $CLI_PATH build/p4src/alg-0.2.p4.json | grep ntp_counter
for i in $(seq 0 15); do
    echo "register_read teste $i" | $CLI_PATH build/p4src/alg-0.2.p4.json | grep teste
done
for i in $(seq 0 15); do
    echo "register_read message_counter $i" | $CLI_PATH build/p4src/alg-0.2.p4.json | grep message_counter
done
