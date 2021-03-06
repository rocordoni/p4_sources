#!/usr/bin/python

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

from scapy.all import sniff
from scapy.all import IP, TCP, UDP

VALID_IPS = ("10.0.0.1", "10.0.0.2", "10.0.0.3")
totals = {}

def handle_pkt(pkt):
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        id_tup = (src_ip, dst_ip, proto, sport, dport)
        if src_ip in VALID_IPS:
            if id_tup not in totals:
                totals[id_tup] = 0
            totals[id_tup] += 1
            print ("Received from %s total: %s" %
                    (id_tup, totals[id_tup]))
    elif IP in pkt and UDP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        id_tup = (src_ip, dst_ip, proto, sport, dport)
        if src_ip in VALID_IPS:
            if id_tup not in totals:
                totals[id_tup] = 0
            totals[id_tup] += 1
            print ("Received from %s total: %s" %
                    (id_tup, totals[id_tup]))

def main():
    sniff(iface = "eth0",
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
