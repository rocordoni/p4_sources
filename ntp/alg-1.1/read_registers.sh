#!/bin/bash

# Copyright 2013-present Barefoot Networks, Inc. 
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

# Modified by Roberto
source /home/rocordoni/Documents/2017-1_TCC/tutorials/env.sh

CLI_PATH=$BMV2_PATH/targets/simple_switch/sswitch_CLI
echo "displaying registers"
for i in $(seq 0 15); do
    echo "register_read ntp_monlist_request_bytes_counter $i" | $CLI_PATH ntp_bytes_asymmetry.json 22222 | grep ntp_monlist_request_bytes_counter
done
for i in $(seq 0 15); do
    echo "register_read ntp_monlist_response_bytes_counter $i" | $CLI_PATH ntp_bytes_asymmetry.json 22222 | grep ntp_monlist_response_bytes_counter
done

echo "register_read ntp_counter 0" | $CLI_PATH heavy_hitter.json 22222 | grep ntp_counter
echo "register_read test 0" | $CLI_PATH heavy_hitter.json 22222 | grep test
echo "register_read amplification_attack 0" | $CLI_PATH heavy_hitter.json 22222 | grep amplification_attack
echo "register_read spoofing_attack 0" | $CLI_PATH heavy_hitter.json 22222 | grep spoofing_attack
