#!/usr/bin/python

"""

Envia requisicoes NTP MONLIST para diversos servidores
"""
from scapy.all import Ether, IP, sendp, get_if_hwaddr, get_if_list, TCP, Raw, UDP, NTP, fuzz
import sys
import time
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

def send_random_traffic(num_of_messages):
    NTP_MONLIST_REQUEST = "\x17\x00\x03\x2a" + "\x00" * 4
    dst_mac = None
    src_ip = None
    dst_ip = None
    legitimate_pkts = 0
    spoofed_pkts = 0
    total_pkts = 0

    # h1 info
    src_ip = '10.0.1.1'
    src_mac = '00:00:00:00:01:01'

    # Dest info
    dst_ip = '10.0.1.3'
    dst_mac = '00:00:00:00:01:99'

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

    # Send request and sleep for some time
    N = int(num_of_messages)
    for i in range(N):
        port = random.randint(1024, 65535)
        p = Ether(dst=dst_mac,src=src_mac)/IP(dst=dst_ip,src=src_ip)
        p = p/UDP(dport=123,sport=port)/NTP(NTP_MONLIST_REQUEST)
        print p.show()
        sendp(p, iface = iface_eth0, loop=0)
        total_pkts += 1

    print ''
    print "Sent %s packets in total" % total_pkts

if __name__ == '__main__':

    if len(sys.argv) < 2:
        print("Usage: python send.py number_of_messages")
        sys.exit(1)
    else:
        num_of_messages = sys.argv[1]
        send_random_traffic(num_of_messages)
