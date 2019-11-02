import socket, sys
from struct import *

class Sniffer(object):
    """
    Sniffer class allows to read raw packets and analyze them

    """

    def __init__(self):
        """
        Initialize Sniffer module

        * defines different header length
        * creates the raw socket to read from

        """
        self.buffer = 65565                 # defines standard buffer size
        self.eth_header_length = 14         # ethernet header length !! ATTENTION: could be 18 with VLAN tag !!
        self.arp_header_length = 28         # ARP packet length
        self.ip_header_length = 20          # ip header length
        self.tcp_header_length = 20         # tcp header length
        self.ethertype_protocols = { '0x800':'ipv4', '0x806':'arp', '0x842':'wake-on-lan', '0x22F3':'ietf trill protocol', '0x6003':'decnet phase iv',
                                     '0x8035':'reverse arp', '0x809B':'appletalk ethertalk', '0x80F3':'appletalk arp', '0x8100':'802.1q and 802.1aq',
                                     '0x8137':'ipx', '0x8204':'qnx qnet', '0x86DD':'ipv6', '0x8808':'ethernet flow control', '0x8819':'cobranet',
                                     '0x8847':'mpls unicast', '0x8848':'mpls multicast', '0x8863':'ppoe discovery stage', '0x8864':'ppoe session stage',
                                     '0x887B':'homeplug 1.0 mme', '0x888E':'802.1x', '0x8892':'profinet', '0x889A':'hyperscsi', '0x88A2':'ata over ethernet',
                                     '0x88A4':'ethercat', '0x88A8':'802.1ad and 802.1aq', '0x88AB':'ethernet powerlink', '0x88B8':'goose',
                                     '0x88B9':'gse management services', '0x88CC':'lldp', '0x88CD':'sercos III', '0x88E1':'homeplug av mme',
                                     '0x88E3':'media redundancy protocol', '0x88E5':'802.1ae', '0x88E7':'802.1ah', '0x88F7':'ptp over ethernet',
                                     '0x88FB':'parallel redundancy protocol', '0x8902':'802.1ag', '0x8906':'fcoe', '0x8914':'fcoe initialization protocol',
                                     '0x8915':'roce', '0x891D':'tte', '0x892F':'hsr', '0x9000':'ethernet configuration testing protocol',
                                     '0x9100':'802.1q with double tag' }

        # create raw socket to read ethernet frames as well
        try:
            self.__s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        except socket.error as msg:
            print('Socket could not be created. Error code: ' + str(msg[0]) + ' Message ' + msg[1])
            sys.exit()

        return

    def __eth_addr(self, raw_mac):
        """
        Returns mac address in human readable hex

        """
        mac = '{:2x}:{:2x}:{:2x}:{:2x}:{:2x}:{:2x}'.format(raw_mac[0], raw_mac[1], raw_mac[2], raw_mac[3], raw_mac[4], raw_mac[5])
        return mac

    def read_packet(self):
        """
        Reads the packet from the socket with defined buffer length

        """
        self.__packet = self.__s.recvfrom(self.buffer)
        self.__packet = self.__packet[0]

        return

    def __read_ethernet_header(self):
        """
        Reads the source mac, destination mac an protocol id out of the ethernet header

        """
        ethernet_header = self.__packet[:self.eth_header_length]

        # !=network (big-endian)
        # s=char[] (byte)
        # H=unsigned short (int,size=2)
        ethernet_header_unpacked = unpack('!6s6sH', ethernet_header)

        d_mac = self.__eth_addr(ethernet_header_unpacked[0])
        s_mac = self.__eth_addr(ethernet_header_unpacked[1])
        ethertype = hex(ethernet_header_unpacked[2])

        ethernet_data = {"d_mac":d_mac, "s_mac":s_mac, "ethertype":self.ethertype_protocols[str(ethertype)]}
        return ethernet_data
        #return self.ethertype_protocols[str(ethertype)]

    def __read_arp_header(self):
            arp_header = self.__packet[self.eth_header_length:self.eth_header_length + self.arp_header_length]

            # !=network (big-endian)
            # s=char[] (byte)
            arp_header_unpacked = unpack('!2s2s1s1s2s6s4s6s4s', arp_header)

            operation = arp_header_unpacked[4]
            s_mac = self.__eth_addr(arp_header_unpacked[5])
            s_addr = socket.inet_ntoa(arp_header_unpacked[6])
            d_mac = self.__eth_addr(arp_header_unpacked[7])
            d_addr = socket.inet_ntoa(arp_header_unpacked[8])

            arp_data = {"operation":operation, "s_mac":s_mac, "s_addr":s_addr, "d_mac":d_mac, "d_addr":d_addr}
            return arp_data

    def __read_ipv4_header(self):
        # Parse IP header
        # take first 20 characters for the ip header
        ip_header = self.__packet[self.eth_header_length:self.eth_header_length + self.ip_header_length]

        # !=network (big-endian)
        # B=unsigned char (int,size=1)
        # H=unsigned short (int,size=2)
        # s=char[] (byte)
        ip_header_unpacked = unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = ip_header_unpacked[0]
        version = version_ihl >> 4

        ttl = ip_header_unpacked[5]
        protocol = ip_header_unpacked[6]
        s_addr = socket.inet_ntoa(ip_header_unpacked[8])
        d_addr = socket.inet_ntoa(ip_header_unpacked[9])

        ipv4_data = {"version":version, "ttl":ttl, "protocol":protocol, "s_addr":s_addr, "d_addr":d_addr}
        return ipv4_data

    def __read_tcp_header(self):
        prefix_header_length = self.eth_header_length + self.ip_header_length
        tcp_header = self.__packet[prefix_header_length:prefix_headers + self.tcp_header_length]

        return

    def get_src_mac(self):
        return self.__read_ethernet_header()['s_mac']

    def get_dst_mac(self):
        return self.__read_ethernet_header()['d_mac']

    def get_ethertype(self):
        return self.__read_ethernet_header()['ethertype']

    def get_arp_src_mac(self):
        return self.__read_arp_header()['s_mac']

    def get_arp_dst_mac(self):
        return self.__read_arp_header()['d_mac']

    def get_arp_src_ip(self):
        return self.__read_arp_header()['s_addr']

    def get_arp_dst_ip(self):
        return self.__read_arp_header()['d_addr']

    def get_ip_version(self):
        return self.__read_ipv4_header()['version']

    def get_src_ip(self):
        return self.__read_ipv4_header()['s_addr']

    def get_dst_ip(self):
        return self.__read_ipv4_header()['d_addr']

if __name__ == "__main__":
    p = Sniffer()

    while True:
        p.read_packet()
        print('Src MAC: ' + p.get_src_mac() + ' | Dest MAC: ' + p.get_dst_mac())
        if p.get_ethertype() == 'ipv4':
            if p.get_ip_version() == 4:
                print('IP Version: ' + str(p.get_ip_version()) + ' | Src IP: ' + p.get_src_ip() + ' | Dest IP: ' + p.get_dst_ip())
            else:
                print('ATTENTION: EVASION (Ethertype: ' + p.get_ethertype() + ' | IP Header Version: ' + str(p.get_ip_version()) + ')')
        elif p.get_ethertype() == 'arp':
            print('Protocol: ARP | Src MAC: ' + str(p.get_arp_src_mac()) + ' | Src IP: ' + str(p.get_arp_src_ip()) + ' | Dest MAC: ' + str(p.get_arp_dst_mac()) + ' | Dest IP: ' + str(p.get_arp_dst_ip()))
        else:
            print('Ethertype: ' + str(p.get_ip_version()))

