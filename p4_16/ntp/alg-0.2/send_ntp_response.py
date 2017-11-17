#!/usr/bin/python

"""
Envia respostas NTP MONLIST para host. Nao importa os camps de origem pq o switch
analisa somente os dados da vitima.
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

def send_random_traffic(host, num_of_messages):
    NTP_ITEMS = "\x02"
    NTP_ITEMS_INT = 2
    NTP_MONLIST_RESPONSE = "\xd7\x00\x03\x2a" + "\x00" + NTP_ITEMS + "\x00\x48" + "\x00" * 72 * NTP_ITEMS_INT
    dst_mac = None
    src_ip = None
    dst_ip = None
    legitimate_pkts = 0
    spoofed_pkts = 0
    total_pkts = 0
    
    # host info --  can be anything
    src_ip = '10.0.1.99'
    src_mac = '00:00:00:00:01:99'
    
    # Dest info
    dst_ip = '10.0.1.' + host.split('h')[1]
    dst_mac = '00:00:00:00:01:0' + host.split('h')[1]

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
        p = p/UDP(dport=123,sport=port)/NTP(NTP_MONLIST_RESPONSE)
        print p.show()
        sendp(p, iface = iface_eth0, loop=0)
        total_pkts += 1

    print ''
    print "Sent %s packets in total" % total_pkts

if __name__ == '__main__':

    if len(sys.argv) < 2:
        print("Usage: python send.py host number_of_messages")
        sys.exit(1)
    else:
        host = sys.argv[1]
        num_of_messages = sys.argv[2]
        send_random_traffic(host, num_of_messages)
