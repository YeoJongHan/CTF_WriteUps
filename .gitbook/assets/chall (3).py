#!/usr/bin/env python3

from Crypto.Util.number import getPrime, getRandomInteger, bytes_to_long
import math
from secret import flag

p,q = [getPrime(512) for _ in range(2)]
n = p*q
e = 65537

a = getRandomInteger(128)
m = bytes_to_long(flag)
ct = pow(m,e,n)

print(f"{p-q=}")
print(f"{pow(p,3)-pow(q,3)=}")
print(f"{n=}")
print(f"{ct=}")