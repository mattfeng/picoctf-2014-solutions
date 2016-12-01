#!/usr/bin/env python

from pwn import *

enc = open('./encrypted', 'rb').read()

for i in range(0, 256):
	print xor(enc, i)
	print '-' * 40