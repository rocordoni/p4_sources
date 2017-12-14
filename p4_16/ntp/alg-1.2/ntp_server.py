#!/usr/bin/python

from scapy.all import sniff, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, TCP, UDP, NTP, ICMP
from scapy.all import send, sendp, Raw
import socket
import fcntl
import struct

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def handle_pkt(pkt, iface):
    my_mac = get_if_hwaddr(iface)
    my_ip = get_ip_address(iface)

    NTP_ITEMS = "\x06"
    NTP_ITEMS_INT = 6
    NTP_MONLIST_RESPONSE = "\xd7\x00\x03\x2a" + "\x00" + NTP_ITEMS + "\x00\x48" + "\x00" * 72 * NTP_ITEMS_INT
    if UDP in pkt and IP in pkt and pkt[IP].src != my_ip :
        src_mac = my_mac
        dst_mac = pkt[Ether].dst
        src_ip = my_ip
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        # Respond with 10 packages with 6 items each = 60 items * 72 bytes = 4320 data bytes
        p = Ether(dst=my_mac,src=dst_mac)/IP(dst=pkt[IP].src,src=my_ip)
        p = p/UDP(dport=123,sport=123)/Raw(NTP_MONLIST_RESPONSE)
        sendp(p, iface = iface, loop=0, verbose=0)
        sendp(p, iface = iface, loop=0, verbose=0)
        sendp(p, iface = iface, loop=0, verbose=0)
        sendp(p, iface = iface, loop=0, verbose=0)
        sendp(p, iface = iface, loop=0, verbose=0)
        sendp(p, iface = iface, loop=0, verbose=0)
        sendp(p, iface = iface, loop=0, verbose=0)
        sendp(p, iface = iface, loop=0, verbose=0)
        sendp(p, iface = iface, loop=0, verbose=0)
        sendp(p, iface = iface, loop=0, verbose=0)

def main():
    iface_eth0 = ''
    for i in get_if_list():
        if 'eth0' in i or 's0' in i:
            iface_eth0 = i
    if not iface_eth0:
        print 'could not find iface_eth0'
        exit(1)
    sniff(iface = iface_eth0,
          prn = lambda x: handle_pkt(x, iface_eth0))

if __name__ == '__main__':
    main()
