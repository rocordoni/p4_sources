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

echo "resetting registers"
echo "register_reset response_counter" | $CLI_PATH build/p4src/alg-0.1.p4.json
echo "register_reset request_counter" | $CLI_PATH build/p4src/alg-0.1.p4.json
echo "register_reset ntp_counter" | $CLI_PATH build/p4src/alg-0.1.p4.json
echo "register_reset amplification_attack" | $CLI_PATH build/p4src/alg-0.1.p4.json
echo

