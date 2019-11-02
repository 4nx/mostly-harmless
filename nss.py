#!/usr/bin/python3
# 2017
import os
import sys
import argparse
import nmap
from collections import OrderedDict

# const
VERSION = '0.2'

# vars
verbose = False

def scan_targets(targets,ports,verbose):
    nm = nmap.PortScanner()
    print_targets = ','.join(targets)
    scan_targets = print_targets.split(',')
    scan_ports = ','.join(ports)

    if verbose:
        print('Start scanning host(s): {}'.format(print_targets))

    for target in scan_targets:
        nm.scan(target,scan_ports)
    
        if verbose:
            for host in nm.all_hosts():
                print('----------------------------------------------------')
                print('Host:\t\t{} ({})'.format(host, nm[host].hostname()))
                print('State:\t\t{}'.format(nm[host].state()))
                print('Scanned ports:\t{}'.format(scan_ports))
                print('----------------------------------------------------')
                for proto in nm[host].all_protocols():
                    print('Protocol: {}'.format(proto.upper()))
                    print('----------')
        
                    lport = list(nm[host][proto].keys())
                    lport.sort()
                    for port in lport:
                        print('Port: {}\tState: {}'.format(port,nm[host][proto][port]['state']))
                        if nm[host][proto][port]['state'] != 'closed':
                            if nm[host][proto][port]['product'] != '':
                                print('|_Product: {}'.format(nm[host][proto][port]['product']))
                            if nm[host][proto][port]['version'] != '':
                                print('|_Version: {}'.format(nm[host][proto][port]['version']))
                            if nm[host][proto][port]['extrainfo'] != '':
                                print('|_Info: {}'.format(nm[host][proto][port]['extrainfo']))

    #print nm.scaninfo()
    #print(nm.get_nmap_last_output(), file=sys.stderr)

def main(arguments):
    parser = argparse.ArgumentParser(description='Network Security Scanner ' + VERSION)
    parser.add_argument('-i', '--ip', required=True, nargs='+', help="ip address of target to scan")
    parser.add_argument('-p', '--ports', nargs='+', help="ports that should be scanned")
    parser.add_argument('-v', '--verbose', help="increase output verbosity", action="store_true")
    args = parser.parse_args()

    scan_targets(args.ip,args.ports,args.verbose)

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
