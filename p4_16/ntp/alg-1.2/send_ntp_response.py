#!/usr/bin/python

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

def send_random_traffic(src_switch, src_host, dst_switch, dst_host, timeout, loop):
    NTP_ITEMS = "\x06"
    NTP_ITEMS_INT = 6
    NTP_MONLIST_RESPONSE = "\xd7\x00\x03\x2a" + "\x00" + NTP_ITEMS + "\x00\x48" + "\x00" * 72 * NTP_ITEMS_INT
    
    src_host_in_hex = '{:02x}'.format(int(src_host))
    dst_host_in_hex = '{:02x}'.format(int(dst_host))
    src_mac = '00:00:00:00:0' + src_switch + ':' + src_host_in_hex
    src_ip  = '10.0.' + src_switch + '.' + src_host
    dst_mac = '00:00:00:00:0' + dst_switch + ':' + dst_host_in_hex
    dst_ip  = '10.0.' + dst_switch + '.' + dst_host
    
    print 'From:\n  ' + src_mac
    print '  ' + src_ip
    print 'To:\n  ' + dst_mac
    print '  ' + dst_ip
    # Get name of eth0 interface
    iface_eth0 = ''
    for i in get_if_list():
        if 'eth0' in i or 's0' in i:
            iface_eth0 = i

    while True:
        # Send with 20 packages with 6 items each = 60 items * 72 bytes = 4320 data bytes
        p = Ether(dst=dst_mac,src=src_mac)/IP(dst=dst_ip,src=src_ip)
        p = p/UDP(dport=123,sport=123)/Raw(NTP_MONLIST_RESPONSE)
        sendp(p, iface = iface_eth0, loop=loop, verbose=0)
        sendp(p, iface = iface_eth0, loop=loop, verbose=0)
        sendp(p, iface = iface_eth0, loop=loop, verbose=0)
        sendp(p, iface = iface_eth0, loop=loop, verbose=0)
        sendp(p, iface = iface_eth0, loop=loop, verbose=0)
        sendp(p, iface = iface_eth0, loop=loop, verbose=0)
        sendp(p, iface = iface_eth0, loop=loop, verbose=0)
        sendp(p, iface = iface_eth0, loop=loop, verbose=0)
        sendp(p, iface = iface_eth0, loop=loop, verbose=0)
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
