#!/usr/bin/python

import sys
import re
from datetime import datetime
import matplotlib.pyplot as plt

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python clients_stats.py [request|response]")
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
            for k,v in sorted(requests.iteritems()):
                print 'Requests from ' + k + ': ' + str(len(v))

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
            for k,v in sorted(responses.iteritems()):
                print 'Responses to ' + k + ': ' + str(len(v))

