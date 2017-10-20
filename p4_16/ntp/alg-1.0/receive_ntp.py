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
from scapy.all import Ether, IP, TCP, UDP, NTP
from scapy.all import send, sendp

VALID_IPS = ("10.0.0.1", "10.0.0.2", "10.0.0.3")
totals = {}
h2_ip = "10.0.0.2"
def handle_pkt(pkt):
    NTP_MONLIST_RESPONSE = "\xd7\x00\x03\x2a" + "\x00\x01\x00\x24" + "\x00" * 64
    if IP in pkt and UDP in pkt and pkt[IP].src != h2_ip:
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst
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
        # Respond with random payload
        p = Ether(dst=src_mac,src=dst_mac)/IP(dst=pkt[IP].src,src=pkt[IP].dst)
        p = p/UDP(dport=pkt[UDP].sport,sport=123)/NTP(NTP_MONLIST_RESPONSE)
        print p.show()
        sendp(p, iface = "eth0", loop=0)

def main():
    sniff(iface = "eth0",
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
