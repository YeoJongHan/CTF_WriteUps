#!/usr/bin/env python3

v = "0 0 0 1 1 2 2 1 2 0 2 1 1 3 0 2 1 0 2 2 1 2 1 1 2 0 0 2 1 0 2 2 3 2 2 2 1 2 1 3 0 0 0 1"

v = v.split(" ")

#mov char into X0
#mov 20 into X19
#sub X0 and X19 and mov result into X0
#mov 4 into X19
#unsigned divide X0 from X19 and mov result into X20
#mulitply subtract, multiple X20 with X19, subtract result from X0, and store result in X21
#mov X21 to X0

#60-20=40 > X0
#4 > X19
#40/4=10 > X20
#10*4=40, 40-40=0

#62-20=42 > X0
#4 > X19
#42/4=10 > X20
#10*4=40, 42-40 = 2

# virus2 is a modulus calc, with 4 as mod

def virus2(flag):
	r = []
	for char in flag:
		temp = ord(char) - 20
		r.append(str(temp%4))
	return ' '.join(r)

print(virus2("TllQezByZDFuYWxfYXNzM21ibHlfMXNfczBfYzAwTH0="))
