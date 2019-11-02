#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#    IPInfo
#
#    Copyright (c) 2018 Simon Krenz
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; Applies version 2 of the License.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

__version__ = '0.1'
__author__ = 'Simon Krenz'

__doc__ = """
IPInfo

 by Simon Krenz

Informationen gathering script for ip addresses.

Features:
    - Recursive DNS lookups
    - Check rDNS results for valid vhosts, redirections etc.

"""
from argparse import ArgumentParser
from datetime import datetime
from os.path import basename
from urllib import request
import socket
import sys
import textwrap

class InfoRake:
    """
    Define arguments and check if ip address is valid.

    :param ip: IP address.
    """
    def __init__(self, address, verbose):
        self.verbose = verbose

        if self._is_valid_ipv4_address(address) or self._is_valid_ipv6_address(address):
            self.ip = address
        else:
            print('Error: {0} is not a valid ip address.'.format(arg))
            sys.exit(2)

        self._main()

    """
    Reverse DNS lookup.

    :param address: An IP address to check.
    """
    def _lookup_rdns(self):
        CHECK_NAME= 'rDNS ({ip})'.format(ip=self.ip)

        try:
            if self.verbose:
                print('rDNS lookup: {}'.format(self.ip))
            hostname, aliases, ipaddrlist = socket.gethostbyaddr(self.ip)
        except socket.herror as err:
            return [CHECK_NAME, err, 2]

        if hostname and aliases:
            aliases.pop(0)
            self.domain_list = [hostname] + aliases
        else:
            self.domain_list = [hostname]

        if self.domain_list:
            return [CHECK_NAME, ', '.join(self.domain_list), 3]
        else:
            return [CHECK_NAME, '--', 1]

    """
    Check if A-Record and recursive DNS are the same.

    :param domain: Domain for A-/AAAA-Record lookup.
    """
    def _lookup_a_record(self, domain):
        try:
            if self.verbose:
                print('DNS lookup: {}'.format(domain))
            info = socket.getaddrinfo(domain, None)[0]
        except socket.error as err:
            return ['A-/AAAA-Record ({})'.format(domain), err, 2]

        resolved_addr = info[4][0]
        if self.ip == resolved_addr:
            return ['A-/AAAA-Record ({})'.format(domain), '{}'.format(resolved_addr), 0]
        else:
            return ['A-/AAAA-Record ({})'.format(domain), '{}'.format(resolved_addr), 1]

    """
    Check if IP is a valid IPv4 address.

    :param address: IP address to be checked
    """
    def _is_valid_ipv4_address(self, address):
        try:
            socket.inet_pton(socket.AF_INET, address)
        except AttributeError:
            try:
                socket.inet_aton(address)
            except socket.error:
                return False
            return address.count('.') == 3
        except socket.error:
            return False

        return True

    """
    Check if IP is a valid IPv6 address.

    :param address: IP address to be checked
    """
    def _is_valid_ipv6_address(self, address):
        try:
            socket.inet_pton(socket.AF_INET6, address)
        except socket.error:
            return False

        return True

    def _print_category_header(self, message):
        print('{underline}{bold} {message} {end}\n'.format(
            underline=bcolors.UNDERLINE,
            bold=bcolors.BOLD,
            message=message,
            end=bcolors.ENDC
            ))
        return True

    def _draw_results(self, table):
        """
        Get the longest string from nested table and add 15 to it's length,
        because of color formatting.
        """
        left_alignment = len(max(table, key=lambda x: len(x[0]))[0]) + 15

        for item in table:
            message_formatted = '{bold} {check_name} {end}'.format(
                bold=bcolors.BOLD,
                check_name=item[0],
                end=bcolors.ENDC
                )
            print('{message:<{align}}'.format(
                message=message_formatted,
                align=left_alignment
                ),end='',flush=True)

            if item[2] == 0:
                print('{ok}OK{end} ({message})'.format(
                    ok=bcolors.OKGREEN,
                    end=bcolors.ENDC,
                    message=item[1]
                    ))
            elif item[2] == 1:
                print('{warning}NOT OK{end} ({message})'.format(
                    warning=bcolors.WARNING,
                    end=bcolors.ENDC,
                    message=item[1]
                    ))
            elif item[2] == 2:
                print('{red}ERROR{end} ({message})'.format(
                    red=bcolors.FAIL,
                    end=bcolors.ENDC,
                    message=item[1]
                    ))
            elif item[2] == 3:
                if len(item[1]) > (80 - left_alignment):
                    print('{message}'.format(
                        message=textwrap.fill(
                            item[1],
                            width=70,
                            subsequent_indent=' ' * (left_alignment - 8)
                            )
                        ))
                else:
                    print('{message}'.format(
                        message=item[1]
                        ))

    def _category_dns_config(self):
        self._print_category_header('Check DNS configurations')

        self._draw_results(self._lookup_rdns())

        for domain in self.domain_list:
            self._draw_results(self._lookup_a_record(domain))


    def _main(self):
        date_start = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        print('\n{bg}{black} Start {time}\t-->> Analyzing: {ip} <<--{end}\n'.format(
            bg=bcolors.BGGREY,
            black=bcolors.BLACK,
            time=date_start,
            ip=self.ip,
            end=bcolors.ENDC
        ))
        self._category_dns_config()


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLACK = '\033[30m'
    BGGREY = '\033[47m'

if __name__ == "__main__":
    basename = basename(__file__)

    parser = ArgumentParser(description='INFORake {0}'.format(__version__))
    parser.add_argument('ip', help='ip address to analyze')
    parser.add_argument('-v', '--verbose', action='store_true', help='increase output verbosity')
    parser.add_argument('--version', action='version', version=__version__, help='show version')
    args = parser.parse_args()

    InfoRake(args.ip, args.verbose)
