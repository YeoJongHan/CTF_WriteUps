#!/usr/bin/env python3

v1 = "48 66 66 48 63 81 39 78 57 36 42 75 54 57 75 66 54 51 48 81 45 27 24 66 63 39 66 66 45 51 48 66 66 81 39 66 54 81 36 81 48 39 21 33"
v2 = "0 0 0 1 1 2 2 1 2 0 2 1 1 3 0 2 1 0 2 2 1 2 1 1 2 0 0 2 1 0 2 2 3 2 2 2 1 2 1 3 0 0 0 1"

v1 = v1.split(' ')
v2 = v2.split(' ')

flag = []

for i in range(len(v1)):
	res = int(v1[i])/3
	m = res - int(v2[i])
	char = (m*4) + int(v2[i]) + 20
	flag.append(chr(int(char)))

print(''.join(flag))

#flag = NYP{0rd1nal_ass3mbly_1s_s0_c00L}