#!/bin/bash

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

# Modified by Roberto
source /home/rocordoni/Documents/2017-1_TCC/tutorials/env.sh

CLI_PATH=$BMV2_PATH/targets/simple_switch/sswitch_CLI
max=2
echo "displaying registers"
for i in $(seq 0 $max); do
    echo "register_read amplification_attack $i" | $CLI_PATH build/p4src/alg-1.2.p4.json | grep amplification_attack
done
#echo "register_read ntp_counter 0" | $CLI_PATH build/p4src/alg-1.2.p4.json | grep ntp_counter
#for i in $(seq 0 $max); do
    #echo "register_read ntp_monlist_request_bytes_counter $i" | $CLI_PATH build/p4src/alg-1.2.p4.json | grep ntp_monlist_request_bytes_counter
#done
for i in $(seq 0 $max); do
    echo "register_read ntp_monlist_response_bytes_counter $i" | $CLI_PATH build/p4src/alg-1.2.p4.json | grep ntp_monlist_response_bytes_counter
done
for i in $(seq 0 $max); do
    echo "register_read amplification_attack_timestamp $i" | $CLI_PATH build/p4src/alg-1.2.p4.json | grep amplification_attack_timestamp
done
