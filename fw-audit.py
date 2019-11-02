#!/usr/local/bin/python3.5
import re
import sys
from pprint import pprint


class Stormshield:
    def __init__(self):
        self.objects = {}

    def read_host_objects(self, host_file):
        host_separator = 'Host'
        host_pattern = re.compile('([a-zA-Z0-9_\-.]+)=(?:([0-9]{1,3}(?:.[0-9]{1,3}){3})\-([0-9]{1,3}(?:\.[0-9]{1,3}){3})|([0-9]{1,3}(?:.[0-9]{1,3}){3}))(?:,)?(?:resolve=)?(dynamic|static)?(([0-9a-f]{0,4}\:){1,7}[0-9a-f]{1,4}|([0-9]{1,3}\.){3}[0-9]{1,3})?')
        host_exclude_rfc4291 = re.compile('rfc4291.*')

        host_objects = self.read_objects(host_file, host_separator, host_pattern, host_exclude_rfc4291)

        for item in host_objects:
            self.host_name = item[0]
            self.host_range_start = item[1]
            self.host_range_end = item[2]
            self.host_ip = item[3]
            self.host_ipv6 = item[5]
            self.host_resolve_type = item[4]

            if self.host_ip is not None:
                print("Host: {} IP: {} Type: {}".format(self.host_name, self.host_ip, self.host_resolve_type))
            if self.host_ipv6 is not None:
                print("Host: {} IP: {} IPv6: {} Type: {}".format(self.host_name, self.host_ip, self.host_ipv6, self.host_resolve_type))
            if self.host_range_start is not None:
                print("Range: {} Start: {} End: {}".format(self.host_name, self.host_range_start, self.host_range_end))

    def read_network_objects(self, network_file):
        network_separator = 'Network'
        network_pattern = re.compile(r'([a-zA-Z0-9\+_\-]*)=([0-9]+(?:\.[0-9]+){3})/([0-9]{,2})')
        network_exclude_v6 = re.compile(r'^IANA_v6.*$')

        network_objects = self.read_objects(network_file, network_separator, network_pattern, network_exclude_v6)

        for item in network_objects:
            self.network_name = item[0]
            self.network_subnet = item[1]
            self.network_mask = item[2]

            print("Network: {} Subnet: {}/{}".format(self.network_name,self.network_subnet,self.network_mask))

    def read_service_objects(self, service_file):
        service_separator = 'Service'
        service_pattern = re.compile(r'([a-zA-Z0-9_\-]*)=([0-9-]*)/([tcp|udp|any]*)')

        service_objects = self.read_objects(service_file, service_separator, service_pattern)

        for item in service_objects:
            self.service_name = item[0]
            self.service_port = item[1]
            self.service_protocol = item[2]

            print("Service: {} Port: {}/{}".format(self.service_name,self.service_protocol,self.service_port))

    def read_firewall_rules(self, filter_file):
        filter_separator = 'Filter'
        filter_pattern = re.compile(r'^pass\s.*?(?:ipproto\s)?(icmp)?(?:\sproto\snone)?\sfrom\s([a-zA-Z0-9_\-\|\+\.]*)\sto\s([a-zA-Z0-9_\-\|\+\.]*)(?:\sport\s)?([a-zA-Z0-9_\-\|]*)(?:\s*#\s)?(.*)')
        filter_exclude_separator = re.compile(r'^(block|reset|separator).*')

        filter_objects = self.read_objects(filter_file, filter_separator, filter_pattern, filter_exclude_separator)

        for item in filter_objects:
            self.filter_ipproto = item[0]
            self.filter_source = item[1]
            self.filter_destination = item[2]
            self.filter_service = item[3]
            self.filter_comment = item[4]

            print("[IPproto: {}] SRC: {} -> DST: {} | Port: {} | Comment: {}".format(self.filter_ipproto, self.filter_source, self.filter_destination, self.filter_service, self.filter_comment))

    def read_objectgroups(self, objectgroup_file):
        group_pattern = re.compile('^\[([a-zA-Z0-9_\-]+)\]$')

        with open(objectgroup_file, 'r') as group_data:
            for line in group_data:
                if group_pattern.search(line.strip()):
                    group_name = group_pattern.search(line.strip()).group(1)
                    print(group_name)
                    break

            for line in group_data:
                group_member = line.strip()

                if group_member == '':
                    break

                print("Group: {} Member: {}".format(group_name,group_member))

    def read_objects(self, source_file, separator, pattern, *exclusions):
        objects = list()

        with open(source_file, 'r') as object_data:
            for line in object_data:
                if line.strip() == '[' + separator + ']':
                    break

            for line in object_data:
                object = line.strip()
                next_line = 0

                if object == '':
                    break

                # Exclusions for config files
                for exclusion in exclusions:
                    if exclusion.search(object):
                        next_line = 1

                if next_line:
                    continue

                try:
                    object = pattern.search(object).groups()
                except AttributeError:
                    print('Unknown line: ' + object)
                    continue

                objects.append(object)

        object_data.close()
        return objects

if __name__ == "__main__":

    object_file = '/home/foo/scripts/files/object.dat'
    objectgroup_file = '/home/foo/scripts/files/objectgroup.dat'
    filter_file = '/home/foo/scripts/files/05.dat'

    audit = Stormshield()
    #audit.read_host_objects(object_file)
    #audit.read_network_objects(object_file)
    #audit.read_service_objects(object_file)
    #audit.read_firewall_rules(filter_file)
    audit.read_objectgroups(objectgroup_file)
