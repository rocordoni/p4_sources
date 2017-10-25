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

def send_random_traffic(dst):
    NTP_MONLIST_REQUEST = "\x17\x00\x03\x2a" + "\x00" * 4
    #NTP_MONLIST_RESPONSE = "\xd7\x00\x03\x2a" + "\x00" * 4
    NTP_MONLIST_RESPONSE = "\xd7\x00\x03\x2a" + "\x00\x01\x00\x24" + "\x00" * 64
    dst_mac = None
    src_ip = None
    dst_ip = None
    legitimate_pkts = 0
    spoofed_pkts = 0
    total_pkts = 0

    # List used to get a random IP source
    ips_list = ['10.0.1.1','10.0.1.2','10.0.1.3']

    # Map IP to respective mac
    # This is needed when trying to send spoofed packet
    # We must match IP source with MAC source.
    mac_addresses = { '10.0.1.1' : "00:00:00:00:01:01",
                      '10.0.1.2' : "00:00:00:00:01:02",
                      '10.0.1.3' : "00:00:00:00:01:03" }
    # Get name of eth0 interface
    iface_eth0 = ''
    for i in get_if_list():
        if 'eth0' in i or 's0' in i:
            iface_eth0 = i
    mac_iface_eth0 = get_if_hwaddr(iface_eth0)
    ip_addr_eth0 = get_ip_address(iface_eth0)

    if len(mac_iface_eth0) < 1:
        print ("No interface for output")
        sys.exit(1)

    if dst == 'h1':
        dst_mac = "00:00:00:00:01:01"
        dst_ip = "10.0.1.1"
    elif dst == 'h2':
        dst_mac = "00:00:00:00:01:02"
        dst_ip = "10.0.1.2"
    elif dst == 'h3':
        dst_mac = "00:00:00:00:01:03"
        dst_ip = "10.0.1.3"
    else:
        print ("Invalid host to send to")
        sys.exit(1)

    N = 10
    for i in range(N):
        # Choose random source IP
        random_number = random.randint(0,2)
        src_ip = ips_list[random_number]
        # Legitimate packet.
        # Increment counter and set source mac
        if src_ip == ip_addr_eth0:
            legitimate_pkts += 1
            src_mac = mac_iface_eth0
        # Spoofed packet
        # Match source IP with correspondent mac address
        else:
            src_mac = mac_addresses[src_ip]
            spoofed_pkts += 1
        port = random.randint(1024, 65535)
        p = Ether(dst=dst_mac,src=src_mac)/IP(dst=dst_ip,src=src_ip)
        p = p/UDP(dport=123,sport=port)/NTP(NTP_MONLIST_REQUEST)
        print p.show()
        sendp(p, iface = iface_eth0, loop=0)
        total_pkts += 1

    print ''
    print "Sent %s legitimate packets" % legitimate_pkts
    print "Sent %s spoofed packets" % spoofed_pkts
    print "Sent %s packets in total" % total_pkts

if __name__ == '__main__':

    if len(sys.argv) < 2:
        print("Usage: python send.py dst_host_name")
        sys.exit(1)
    else:
        dst_name = sys.argv[1]
        send_random_traffic(dst_name)
