#!/usr/bin/python

import sys
import re
from datetime import datetime
import matplotlib.pyplot as plt

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
                for line in f.readlines():
                    r = re.search('^\[(\d+:\d+:.+)\]\s\[bmv2.*hdr.ntp_first.r == 0" is true', line)
                    if r:
                        datetime_object = datetime.strptime(r.group(1).strip(), '%H:%M:%S.%f')
                        t = datetime_object - t0
                        # After found a request, get the host which sent the message
                        with open(filename, 'r') as f2:
                            regex = re.compile(r"^\[" + str(r.group(1))[:-1] + "\d*\](.+)Applying table \'show_src_addr_in_log\'\n^\[" + str(r.group(1))[:-1] + "\d*\](.+)\n^(.+)ipv4.+:\s+(.+)", re.MULTILINE)
                            m = regex.search(f2.read())
                            if m:
                                host = m.group(4)
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
            plt.scatter(*zip(*list_of_tuples), marker="s")
            plt.ylabel('some numbers')
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
                for line in f.readlines():
                    r = re.search('^\[(\d+:\d+:.+)\]\s\[bmv2.*hdr.ntp_first.r == 1" is true', line)
                    if r:
                        datetime_object = datetime.strptime(r.group(1).strip(), '%H:%M:%S.%f')
                        t = datetime_object - t0
                        # After found a response, get the host which sent the message
                        with open(filename, 'r') as f2:
                            regex = re.compile(r"^\[" + str(r.group(1))[:-1] + "\d*\](.+)Applying table \'show_dst_addr_in_log\'\n^\[" + str(r.group(1))[:-1] + "\d*\](.+)\n^(.+)ipv4.+:\s+(.+)", re.MULTILINE)
                            m = regex.search(f2.read())
                            if m:
                                host = m.group(4)
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