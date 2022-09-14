# Lost In the Deep

## Description

> You've been swimming, and encounter a submerged mangrove forest. You enter it to explore, and without knowing it, you're lost. How do you escape?

{% file src="../../../.gitbook/assets/chall.exe" %}

(_Windows Antivirus may pick up virus signatures from the file_)

### TL:DR

* Notice that the executable is packed using UPX, so unpack it
* Through ghidra, find an odd long string that is used in the executable
* Realize that there is a pattern in the characters of the string
* 1st character is expected to be 'S', but it is 'R'. ord('S')-1 = ord('R')
* 2nd character is expected to be 'T', but it is 'V'. ord('T')+2 = ord('V')
* And so on...
* Make a solve script for it
* Flag is won

## Solution

### Analysis

We are given a windows executable file.

Running `strings chall.exe`, we can see strings like `UPX0`, `UPX1`. This indicates that the executable is packed using `UPX`.

![image](https://user-images.githubusercontent.com/83258849/174650032-6c28dd45-daf2-4515-9262-c761be3f8e6f.png)

We can unpack it by running `upx -d chall.exe`.

After that, we can actually decompile and read the code in `ghidra`. However, the executable is stripped so we don't have any debugging symbols to work with. So **no**, we **shouldn't** read the code (possible, but it would be troublesome to do so anyways).

Look at how long the code for this function scrolls down for!

![](https://user-images.githubusercontent.com/83258849/174651984-543f4fcf-a13a-45fd-9543-8316e11d5c43.png)

So I decided to take a different approach.

Looking around the program in `ghidra`, I found a suspicious string used by the program.

![image](https://user-images.githubusercontent.com/83258849/174650687-55fac7ff-da6a-4250-90ee-edc625a1e758.png)

You can look for strings in `ghidra` by navigating to the `Search` tab then selecting `For Strings...`.

![image](https://user-images.githubusercontent.com/83258849/174650797-87ebae18-1e3d-4d23-97e3-5ee8b89c84fa.png)

When you look at the string closely, you can actually make out a pattern.

* 1st character is expected to be 'S', but it is 'R'. ord('S')-1 = ord('R')
* 2nd character is expected to be 'T', but it is 'V'. ord('T')+2 = ord('V')
* 3rd character is expected to be 'A', but it is '>'. ord('A')-3 = ord('>')
* 4th character is expected to be 'N', but it is 'R'. ord('N')+4 = ord('R')
* 5th character is expected to be 'D', but it is '?'. ord('D')-5 = ord('?')
* 6th character is expected to be 'C', but it is 'G'. ord('C')+4 = ord('G')
* 7th character is expected to be 'O', but it is 'L'. ord('O')-3 = ord('L')
* 8th character is expected to be 'N', but it is 'P'. ord('N')+2 = ord('P')
* 9th character is expected to be '2', but it is '1'. ord('2')-1 = ord('1')
* 10th character is expected to be '2', but it is '3'. ord('2')+1 = ord('3')

Note that the pattern adds and subtracts `1` after reaching `5` for the first time.

So pattern would be -1,+2,-3,+4,-5,+4,-3,+2,-1,+1,-2...

Create solve script :)

### Solve.py

```python
#!/usr/bin/env python3

enc = b"RV>R?GLP13yf<s#.]6dg\\/ci\\hnsc8'dbrp`*jbc&vbg4`df/:`i1506/7a90787492j04b956-9.=z"

count = 1
offset = 1
flag = ""
inc = True
off_count = 1
for c in enc:
	if count%2==1:
		flag += chr(c+offset)
	else:
		flag += chr(c-offset)

	if offset == 5:
		inc = False
	elif offset == 1:
		off_count += 1
		if off_count == 2:
			off_count = 0
			inc = True
		else:
			count += 1
			continue
	count += 1
	if inc:
		offset += 1
	else:
		offset -= 1
print(flag)	
```

_Script is not so elegant, but it works_

Flag: `STANDCON22{c@n'+_5ee_+he_fore5+_for_+he_+ree5_fc35df341423f53596666e41d8640539}`
