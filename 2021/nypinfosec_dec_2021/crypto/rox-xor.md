# ROX != XOR

## Description

> Hmm why is it not the same?

> Author: **Ee Sheng**

{% file src="../../../.gitbook/assets/challenge.txt" %}

## The Challenge

### challenge.txt

```
a = "PUG(BDNUIOIBK}"
b = "áóè¬äôäîùþóôàÿ"
```

From the name of the challenge, it is safe to say that it has something to do with `XORing` the two strings that have been given. Other than that, no other clues are given.

We can create a simple python script to xor the two strings together:

```python
a = "PUG(BDNUIOIBK}"
b = "áóè¬äôäîùþóôàÿ"

result = ""
for i in range(len(a)):
	x = ord(a[i]) ^ ord(b[i])
  result += chr(x)
print(result)
```

Sadly, this does not return us any proper characters :(

![](https://user-images.githubusercontent.com/83258849/147683932-20f5d7f4-700b-41dd-88df-8252e587904f.png)

I tried searching online for an `ROX` operation or instruction but couldn't find anything.

The next thing i looked at is checking if there are any patterns in the `decimal` representation of the characters after the `XOR`.

`177 166 175 132 166 176 170 187 176 177 186 182 171 130`

I don't really see any patterns here.

Since we know that the flag would always start with "`NYP{`", let's see their `decimal` representations and compare against the `XOR` characters to see if there are any patterns we can leverage on.

```
177 166 175 132 166 176 170 187 176 177 186 182 171 130 # the encrypted flag
78 89 80 123                                            # decimal representation for NYP{
```

And we see a pattern!

The difference between the 2nd and 1st characters of "`NYP{`" is `89 - 78 = 11`. The diff between the 3rd and 2nd characters is `80 - 89 = -9`, and the diff between the 4th and 3rd characters is `123 - 80 = 43`.

For the encrypted flag, the difference between the 1st and 2nd characters is `177 - 166 = 11`, the diff between 2nd and 3rd is `166 - 175 = -9`, and the diff between the 3rd and 4th characters is `175 - 132 = 43`!

We can now create a python script to automate solving the rest of the flag.

1. Since we want the first character of the encrypted flag to be the character "`N`", we need it to change from `177` to `78`. So we minus the first character of the flag by `99` (177-78=99).
2. To find the next correct number, we must add the current number with the difference between the number at current index in the encrypted flag and the number at the current index + 1 in the encrypted flag. This might be confusing because it is hard to explain, so here is an example:

```python
encrypted_flag = [177, 166, 175, 132]
start = 78 # N in decimal

# Current index of the flag is 0 as it is the first character of the flag
# N is at index 0, which is 78 in decimal
# At index 0 of the encrypted flag is 177
# At index 0+1 of the encrypted flag is 166
# 177 - 166 = 11, this is the difference
# Next character is the difference added to the number at the current index of the flag.
# Current number (character) is 78 (N), 78 + 11 = 89. 89 is our next character in decimal (checking ontop, 89 is indeed "Y")

# Move on to next index of the flag, which is "Y", 89 in decimal
# Y is at index 1
# At index 1 of the encrypted flag is 166
# At index 1+1 of the encrypted flag is 175
# 166 - 175 = -9
# next char is 89 + (-9) = 80 (80 is indeed "P")

# "P" is at index 2, and is 80 in decimal
# index 2 of encrypted flag is 175
# index 2+1 of encrypted flag is 132
# 175 - 132 = 43
# next char is 80 + 43 = 123 (123 is indeed "{")
```

1. After finding correct decimals, convert them to ASCII characters, join them and you get your flag!

## solve.py

```
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
```

flag = `NYP{YOUDONEIT}`

#### Intended solution is probably to inverse the 1s to 0s and 0s to 1s after the XOR. Credits to `Dylan` :D
