#!/usr/bin/env python

from pwn import *
import string
import subprocess as sp
import os

def get_inscount():
	count = open('./inscount.out').read().strip()
	count = int(count.split(' ')[1])
	return count

def mk_input(s):
	s = ''.join(s)
	f = open('./input', 'w')
	print >> f, s.strip()

flag = list('?' * 30)
charset = '_' + string.ascii_lowercase

FNULL = open(os.devnull, 'w')

for i in range(0, 30):

	min_letter = ''
	min_inscount = 2**32

	for c in charset:
		flag[i] = c
		mk_input(flag)
		tmp = ''.join(flag)
		cmd = 'pin -t inscount0.so -- ./baleful < input'
		sp.call(cmd, shell=True, stdout=FNULL, stderr=FNULL)
		inscount = get_inscount()
		log.info('payload: %s, inscount: %s' % (tmp, inscount))
		if inscount < min_inscount:
			log.info('new min flag: %s' % tmp)
			min_letter = c
			min_inscount = inscount

	flag[i] = min_letter

print 'Flag: ' + ''.join(flag)