#!/usr/bin/env python3

v = "48 66 66 48 63 81 39 78 57 36 42 75 54 57 75 66 54 51 48 81 45 27 24 66 63 39 66 66 45 51 48 66 66 81 39 66 54 81 36 81 48 39 21 33"

v = v.split(" ")

#mov char into X0
#mov 20 into X19
#sub X0 and X19 and mov result into X0
#mov 4 into X19
#unsigned divide X0 from X19 and mov result into X20
#mulitply subtract, multiple X20 with X19, subtract result from X0, and store result in X21
#add X21 with X20 and store result in X0

#mov 3 into X19
#multiply X0 with X19 and mov result into X0

#60-20=40 > X0
#4 > X19
#40/4=10 > X20
#10*4=40, 40-40=0 > X21
#0+10=10 > X0
#3 > X19
#10*3=30 > X0

#61-20=41 > X0
#4 > X19
#41/4=10 > X20
#10*4=40, 41-40=1 > X21
#1+10=11 > X0
#3 > X19
#11*3=33 > X0

def virus1(flag):
	r = []
	for char in flag:
		temp = ord(char) - 20
		remainder = temp % 4
		quotient = temp // 4
		res = (quotient + remainder) * 3
		r.append(str(res))
	return ' '.join(r)

print(virus1("TllQezByZDFuYWxfYXNzM21ibHlfMXNfczBfYzAwTH0="))