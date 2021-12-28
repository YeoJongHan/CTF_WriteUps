#!/usr/bin/env python3


pwd = {
	"4" : 52048,
	"2" : 52081,
	"7" : 52067,
	"3" : 52087,
	"8" : 52080,
	"11" : 52076,
	"10" : 52071,
	"0" : 52035,
	"6" : 52084,
	"9" : 52081,
	"1" : 52063,
	"5" : 52067,
	"12" : 52069
}

final = ""

for i in range(13):
	num = pwd[str(i)] - 0xCafe
	final += chr(num)

print(final)