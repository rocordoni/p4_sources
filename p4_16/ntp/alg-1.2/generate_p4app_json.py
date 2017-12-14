#!/usr/bin/python

import sys

def generate(num_hosts):
    # generate links with each host connected to s1
    string = '"links": ['
    for i in range(1,num_hosts + 1):
        host = 'h' + str(i)
        if i <= 255:
            if i == num_hosts:
                string += '["' + host + '","s1"]'
            else:
                string += '["' + host + '","s1"],'
        elif i > 255 and i <= 65535:
            if i == num_hosts:
                string += '["' + host + '","s2"]'
            else:
                string += '["' + host + '","s2"],'
    string += '],'
    
    string2 = '"hosts": {'
    for i in range(1,num_hosts + 1):
        host = 'h' + str(i)
        if i == num_hosts:
            string2 += '"' + host + '": {}'
        else:
            string2 += '"' + host + '": {},'
    string2 += '},'

    print string
    print string2
    
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python generate_p4app_json.py num_hosts")
        sys.exit(1)
    else:
        generate(int(sys.argv[1]))
        
