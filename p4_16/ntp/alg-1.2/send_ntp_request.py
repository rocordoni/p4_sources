#!/usr/bin/python

from scapy.all import Ether, IP, sendp, get_if_hwaddr, get_if_list, TCP, Raw, UDP, NTP, fuzz
import sys
import time
import string
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

def send_random_traffic(src_switch, src_host, dst_switch, dst_host, timeout, loop):
    NTP_MONLIST_REQUEST = "\x17\x00\x03\x2a" + "\x00" * 8

    src_mac = '00:00:00:00:0' + src_switch + ':0' + src_host
    src_ip  = '10.0.' + src_switch + '.' + src_host
    dst_mac = '00:00:00:00:0' + dst_switch + ':0' + dst_host
    dst_ip  = '10.0.' + dst_switch + '.' + dst_host

    # Get name of eth0 interface
    iface_eth0 = ''
    for i in get_if_list():
        if 'eth0' in i or 's0' in i:
            iface_eth0 = i

    while True:
        p = Ether(dst=dst_mac,src=src_mac)/IP(dst=dst_ip,src=src_ip)
        p = p/UDP(dport=123,sport=123)/Raw(NTP_MONLIST_REQUEST)
        sendp(p, iface = iface_eth0, loop=loop, verbose=0)
        time.sleep(timeout)

if __name__ == '__main__':
    if len(sys.argv) < 6:
        print("Usage: python send.py src_switch src_host dst_switch dst_host time [loop]<0|1>")
        sys.exit(1)
    else:
        src_switch = sys.argv[1]
        if 's' in src_switch:
            src_switch = sys.argv[1].split('s')[1]
        src_host = sys.argv[2]
        if 'h' in src_host:
            src_host = sys.argv[2].split('h')[1]
        dst_switch = sys.argv[3]
        if 's' in dst_switch:
            dst_switch = sys.argv[3].split('s')[1]
        dst_host = sys.argv[4]
        if 'h' in dst_host:
            dst_switch = sys.argv[4].split('h')[1]
        timeout = float(sys.argv[5])
        loop = 1
        if len(sys.argv) > 6:
            loop = int(sys.argv[6])

        send_random_traffic(src_switch, src_host, dst_switch, dst_host, timeout, loop)
