#!/usr/bin/env python

# OP SRC, DEST -> DEST = DEST OP SRC

ebx = 19076
eax = 7343
ecx = 21097


if ebx < eax:	# CMP %eax,%ebx
				# JL L1
	ebx *= eax	# IMUL %eax,%ebx
	ebx += eax	# ADD  %eax,%ebx
	eax = ebx	# MOV  %ebx,%eax
	eax -= ecx  # SUB  %ecx,%eax
else:
	ebx *= eax
	ebx -= eax
	eax = ebx
	eax += ecx

print eax
