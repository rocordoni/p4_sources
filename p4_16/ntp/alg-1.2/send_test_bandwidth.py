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
import socket
import fcntl
import struct

def randomword(max_length):
    length = random.randint(1, max_length)
    return ''.join(random.choice(string.lowercase) for i in range(length))

def set_payload(length):
    return ''.join(random.choice(string.lowercase) for i in range(length))

def gen_random_ip():
    ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
    return ip

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

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

def send_random_traffic():
    NTP_MONLIST_REQUEST = "\x17\x00\x03\x2a" + "\x00" * 4
    NTP_MONLIST_RESPONSE = "\xd7\x00\x03\x2a" + "\x00\x01\x00\x64" + "\x00" * 64
    dst_mac = "00:00:00:00:01:03"
    dst_ip = '10.0.1.3'
    dst_port = 123
    
    # Get name of eth0 interface
    iface_eth0 = ''
    for i in get_if_list():
        if 'eth0' in i or 's0' in i:
            iface_eth0 = i
    src_mac = get_if_hwaddr(iface_eth0)
    src_ip = get_ip_address(iface_eth0)
    print iface_eth0
    print src_mac
    print src_ip

    p = Ether(dst=dst_mac,src=src_mac)/IP(dst=dst_ip,src=src_ip)
    p = p/UDP(dport=123,sport=124)/NTP(NTP_MONLIST_RESPONSE)
    # loop = 1 -> send indefinitely, we have to ctrl + c to stop program
    # verbose = 0 -> no verbose
    sendp(p, iface = iface_eth0, loop=0, verbose=0)

if __name__ == '__main__':

    send_random_traffic()
