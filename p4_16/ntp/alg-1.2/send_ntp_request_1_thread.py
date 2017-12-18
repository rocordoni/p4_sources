#!/usr/bin/python

from scapy.all import Ether, IP, sendp, get_if_hwaddr, get_if_list, TCP, Raw, UDP, NTP, fuzz
import sys
import time
import random, string
import socket
import fcntl
import struct

from threading import Thread

class Th(Thread):

    def __init__ (self, num, src_switch, src_host, dst_switch, dst_host):
        Thread.__init__(self)
        self.num = num
        
        if num <= 255:
            self.src_mac = '00:00:00:00:0' + src_switch + ':0' + src_host
            self.src_ip = '10.0.' + src_switch + '.' + src_host
            self.dst_mac = '00:00:00:00:0' + dst_switch + ':' + hex(int(dst_host)).split('x')[1]
            self.dst_ip  = '10.0.' + dst_switch + '.' + dst_host
        elif num > 255 and num < 511:
            dst_host = str(num - 255)
            self.src_mac = '00:00:00:00:0' + src_switch + ':0' + src_host
            self.src_ip = '10.0.' + src_switch + '.' + src_host
            self.dst_mac = '00:00:00:01:0' + dst_switch + ':' + hex(int(dst_host)).split('x')[1]
            self.dst_ip  = '10.1.' + dst_switch + '.' + dst_host

    def run(self):
        NTP_MONLIST_REQUEST = "\x17\x00\x03\x2a" + "\x00" * 8        
        # Get name of eth0 interface
        iface_eth0 = ''
        for i in get_if_list():
            if 'eth0' in i or 's0' in i:
                iface_eth0 = i
        print self.src_ip
        print self.dst_ip
        p = Ether(dst=self.dst_mac,src=self.src_mac)/IP(dst=self.dst_ip,src=self.src_ip)/UDP(dport=123,sport=123)/Raw(load=NTP_MONLIST_REQUEST)
        # loop = 1 -> send indefinitely, we have to ctrl + c to stop program
        # verbose = 0 -> no verbose
        while keep_going == True:
            timeout = random.randrange(0,5)
            time.sleep(float(timeout))
            sendp(p, iface = iface_eth0, loop=0, verbose=1)
            time.sleep(float(timeout))
        

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

keep_going = True

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python send_ntp_response_threads.py SRCHOST")
        sys.exit(1)
    else:
            i = int(sys.argv[1])
            # send from: s1 h(i), to: s1 h2
            thread = Th(i, '1', str(i), '1', '9')
            thread.start()
            # Run threads for X seconds
            time.sleep(30)
            keep_going = False
