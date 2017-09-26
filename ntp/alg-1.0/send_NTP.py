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

from scapy.all import Ether, IP, sendp, get_if_hwaddr, get_if_list, TCP, Raw, UDP, NTP, fuzz
import sys
import random, string

def randomword(max_length):
    length = random.randint(1, max_length)
    return ''.join(random.choice(string.lowercase) for i in range(length))

def set_payload(length):
    return ''.join(random.choice(string.lowercase) for i in range(length))

def gen_random_ip():
    ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
    return ip

def read_topo():
    nb_hosts = 0
    nb_switches = 0
    links = []
    with open("topo.txt", "r") as f:
        line = f.readline()[:-1]
        w, nb_switches = line.split()
        assert(w == "switches")
        line = f.readline()[:-1]
        w, nb_hosts = line.split()
        assert(w == "hosts")
        for line in f:
            if not f: break
            a, b = line.split()
            links.append( (a, b) )
    return int(nb_hosts), int(nb_switches), links

def send_random_traffic(dst):
    NTP_MONLIST_REQUEST = "\x17\x00\x03\x2a" + "\x00" * 4
    #NTP_MONLIST_RESPONSE = "\xd7\x00\x03\x2a" + "\x00" * 4
    NTP_MONLIST_RESPONSE = "\xd7\x00\x03\x2a" + "\x00\x01\x00\x24" + "\x00" * 64
    dst_mac = None
    dst_ip = None
    src_mac = [get_if_hwaddr(i) for i in get_if_list() if i == 'eth0']
    if len(src_mac) < 1:
        print ("No interface for output")
        sys.exit(1)
    src_mac = src_mac[0]
    src_ip = None
    
    if dst == 'h1':
        dst_mac = "00:00:00:00:00:01"
        dst_ip = "10.0.0.1"
    elif dst == 'h2':
        dst_mac = "00:00:00:00:00:02"
        dst_ip = "10.0.0.2"
    elif dst == 'h3':
        dst_mac = "00:00:00:00:00:03"
        dst_ip = "10.0.0.3"
    else:
        print ("Invalid host to send to")
        sys.exit(1)

    # Create N src ip
    N = 1
    src_ip_list = list()
    src_dict = dict()
    for i in range(0,N):
        src_ip_list.append(gen_random_ip())
    
    total_pkts = 0
    #for src_ip in src_ip_list:
    for src_ip in ['10.0.0.1']:
        num_packets = 10
        port = random.randint(1024, 65535)
        for i in range(num_packets):
            data = set_payload(400)
            p = Ether(dst=dst_mac,src=src_mac)/IP(dst=dst_ip,src=src_ip)
            p = p/UDP(dport=123,sport=port)/NTP(NTP_MONLIST_REQUEST)
            print p.show()
            sendp(p, iface = "eth0")
            total_pkts += 1
            #print('total_pkts untill now: ' + str(total_pkts))
    print "Sent %s packets in total" % total_pkts

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python send.py dst_host_name")
        sys.exit(1)
    else:
        dst_name = sys.argv[1]
        send_random_traffic(dst_name)
