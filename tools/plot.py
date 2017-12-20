#!/usr/bin/python

import sys
import re
from datetime import datetime
import matplotlib.pyplot as plt

def get_attacks(filename):
    attacks = {}
    t0 = None
    # Get start time t0
    with open(filename, 'r') as f:
        for line in f.readlines():
            r = re.search('^\[(\d+:\d+:.+)\]\s\[bmv2(.+)Set default entry for table', line)
            if r:
                t0 = datetime.strptime(r.group(1).strip(), '%H:%M:%S.%f')
                break
    with open(filename, 'r') as f2:
        regex = re.compile(r"Applying table \'amplification_attack_table\'\n\[(\d+:\d+:\d+\.\d+)\].+?ipv4\.\w+\s+:\s+(\w+)", re.DOTALL)
        #regex = re.compile(r"^(\*\s+ipv4\.dstAddr\s+:\s+.*?1)", re.DOTALL)
        m = regex.search(f2.read())
        if m:
            attack_time = datetime.strptime(m.group(1).strip(), '%H:%M:%S.%f')
            t = attack_time - t0
            host = m.group(2)
            host = 'h' + host[-1]
            if host not in attacks.keys():
                attacks[host] = []
            attacks[host].append(t.total_seconds())
    return attacks

def on_click(event):
    # get the x and y coords, flip y from top to bottom
    x, y = event.x, event.y
    if event.button == 1:
        if event.inaxes is not None:
            print('data coords %f %f' % (event.xdata, event.ydata))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python plot.py [request|response]")
        sys.exit(1)
    else:
        filename = '../p4_16/ntp/alg-1.2/build/logs/s1.log'
        if 'req' in sys.argv[1]:
            # Parse requests
            requests = {}
            t0 = None
            # Get start time t0
            with open(filename, 'r') as f:
                for line in f.readlines():
                    r = re.search('^\[(\d+:\d+:.+)\]\s\[bmv2(.+)Set default entry for table', line)
                    if r:
                        t0 = datetime.strptime(r.group(1).strip(), '%H:%M:%S.%f')
                        break
            # Search for requests
            with open(filename, 'r') as f:
                regex = re.compile(r"^\[(\d+:\d+:.+)\]\s\[bmv2.*hdr.ntp_first.r == 0\" is true\n\[\d+:\d+:.+\].+Applying table \'show_src_addr_in_log\'\n\[\d+:\d+:.+\].+\n.+ipv4.+:\s+(.+)", re.MULTILINE)
                for item in regex.finditer(f.read()):
                    datetime_object = datetime.strptime(item.group(1).strip(), '%H:%M:%S.%f')
                    t = datetime_object - t0
                    host = item.group(2)
                    host = 'h' + host[-1]
                    if host not in requests.keys():
                        requests[host] = []
                    requests[host].append(t.total_seconds())

            # This is an amazing step which I found on internet
            # Convert the dict to tuples as (time, host_number).
            list_of_tuples = []
            for k,v in requests.iteritems():
                tmp = [(i, k[-1]) for i in v]
                list_of_tuples += tmp

            attacks = get_attacks(filename)
            list_of_tuples2 = []
            for k,v in attacks.iteritems():
                tmp = [(i, k[-1]) for i in v]
                list_of_tuples2 += tmp
            plt.scatter(*zip(*list_of_tuples), marker="s", color='black')
            plt.scatter(*zip(*list_of_tuples2), marker='v', color='red')
            plt.ylabel('Hosts')
            plt.xlabel('Tempo')
            plt.connect('button_press_event', on_click)
            plt.show()

        if 'resp' in sys.argv[1]:
            # Parse responses
            responses = {}
            t0 = None
            # Get start time t0
            with open(filename, 'r') as f:
                for line in f.readlines():
                    r = re.search('^\[(\d+:\d+:.+)\]\s\[bmv2(.+)Set default entry for table', line)
                    if r:
                        t0 = datetime.strptime(r.group(1).strip(), '%H:%M:%S.%f')
                        break
            # Search for responses
            with open(filename, 'r') as f:
                regex = re.compile(r"^\[(\d+:\d+:.+)\]\s\[bmv2.*hdr.ntp_first.r == 1\" is true\n\[\d+:\d+:.+\].+Applying table \'show_dst_addr_in_log\'\n\[\d+:\d+:.+\].+\n.+ipv4.+:\s+(.+)", re.MULTILINE)
                for item in regex.finditer(f.read()):
                    datetime_object = datetime.strptime(item.group(1).strip(), '%H:%M:%S.%f')
                    t = datetime_object - t0
                    host = item.group(2)
                    host = 'h' + host[-1]
                    if host not in responses.keys():
                        responses[host] = []
                    responses[host].append(t.total_seconds())

            # This is an amazing step which I found on internet
            # Convert the dict to tuples as (time, host_number).
            list_of_tuples = []
            for k,v in responses.iteritems():
                tmp = [(i, k[-1]) for i in v]
                list_of_tuples += tmp
            plt.scatter(*zip(*list_of_tuples), marker="s")
            plt.ylabel('some numbers')
            plt.connect('button_press_event', on_click)
            plt.show()
