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
echo "register_read ntp_counter 0" | $CLI_PATH build/p4src/alg-1.0.p4.json | grep ntp_counter
echo "register_read spoofed_pkts_reg 0" | $CLI_PATH build/p4src/alg-1.0.p4.json | grep spoofed_pkts_reg
echo "register_read ingress_port_reg 0" | $CLI_PATH build/p4src/alg-1.0.p4.json | grep ingress_port_reg
echo "register_read mapped_port_reg 0" | $CLI_PATH build/p4src/alg-1.0.p4.json | grep mapped_port_reg
