#!/usr/bin/python3
import socket, re, sys
from subprocess import Popen, PIPE
from argparse import ArgumentParser

# global variables
dic_full = {}
dic_single = {}
ip = ''

# lockup ip address
def resolve(addr):
	try:
		#  return url, alias and ip inside a list
		return socket.gethostbyaddr(addr)
	except socket.herror:
		return None, None, None

def whois(addr):
	org_name =''
	owner_name = ''
	process = Popen(['/usr/bin/whois', addr], stdout=PIPE)
	while True:
		response = process.stdout.readline()
		if not response: break
		response = response.decode().strip()
		if not response: next
		if re.search(r"OrgName:\s+(.*)", response): org_name = re.search(r"OrgName:\s+(.*)", response)
		if re.search(r"owner:\s+(.*)", response): owner_name = re.search(r"owner:\s+(.*)", response)
	if org_name and owner_name:
		return org_name.group(1), owner_name.group(1)
	elif org_name:
		return org_name.group(1), None
	elif owner_name:
		return None, owner_name.group(1)
	else:
		return None, None

parser = ArgumentParser(description = "IP Analyzer")
parser.add_argument("ip", help="ip address")
parser.add_argument("-w", "--whois", action="store_true", help="whois ip address")
args = parser.parse_args()

ip = args.ip
url, alias, ip_addr = resolve(ip)
print('IP address:\t\t', ip_addr[0])
print('Resolved address:\t', url)
if args.whois:
	org_name, owner_name = whois(ip)
	print('Organisation name: ', org_name)
	print('Owner name: ', owner_name)
