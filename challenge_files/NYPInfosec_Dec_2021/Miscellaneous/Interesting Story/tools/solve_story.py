#!/usr/bin/env python3

f = open('formatted_interesting_story.txt', 'r').read()
a = open('actual_story.txt', 'r').readlines()

story = ""

for i in a:
	story += i.replace('\n', ' ')

fl = f.split(" ")
sl = story.split(" ")

new = []

for i in fl:
	if i not in sl:
		new.append(i)

print(new)

flag = ""
for i in new:
	if 'three' in i:
		flag += '3'
	elif 'one' in i:
		flag += '1'
	elif i == 'leave' or 'recovering' in i or  i =='days':
		continue
	else:
		flag += i[0]

print(flag)
