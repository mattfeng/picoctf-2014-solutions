#!/usr/bin/env python

book = open('./book.txt').read()
book = book.split('\n\n')

book = [p.split('\n') for p in book]

code = [
(1, 9, 4),
(4, 2, 8),
(4, 8, 3),
(7, 1, 5),
(8, 10, 1)
]

for c in code:
	print book[c[0] - 1][c[1] - 1].split(' ')[c[2] - 1]

# ceremonial plates