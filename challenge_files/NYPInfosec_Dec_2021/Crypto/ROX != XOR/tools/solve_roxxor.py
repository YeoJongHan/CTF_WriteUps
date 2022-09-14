#!/usr/bin/env python3

a = "PUG(BDNUIOIBK}"
b = "áóè¬äôäîùþóôàÿ"

temp = 0
flag = ""
for i in range(len(a)):
	print(flag)
	x = ord(a[i]) ^ ord(b[i])
	if temp == 0:
		char = chr(x - 99)
		flag += char
		temp = x

	else:
		diff = temp-x
		char = chr(ord(flag[-1]) + diff)
		flag += char
		print("Diff {}".format(diff))
	temp = x
	print(x, x-99)
	

print("Flag is {}".format(flag))
