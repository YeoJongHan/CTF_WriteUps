# Want a byte?

## Description

> Scrolling through my projects, I found some old project code. I remember this code had some "backdoors". But since I mistakenly deleted utils.py, now I cannot understand my own code! Can you help me make sense out of it? You will be rewarded with a flag for your help.

* [main.py](../../../STANDCON\_2022/Reverse/Want%20a%20byte)
* [utils.pyc](../../../STANDCON\_2022/Reverse/Want%20a%20byte)

{% file src="../../../.gitbook/assets/main.py" %}

{% file src="../../../.gitbook/assets/utils.pyc" %}

###

### TL;DR

* Decompile utils.pyc
* Find out that master\_key is always 'a'\*20
* Notice its just encrypting the flag by xoring each character of the flag with 'a's
* Xor the encrypted flag with 'a's
* Win flag

## Analysis

We have to first decompile [utils.pyc](../../../STANDCON\_2022/Reverse/Want%20a%20byte) to understand the functions that reside in it.

Using `decompyle3`, it indicates that the file is coded in Python2.7. This guy really needs to upgrade his Python.

![](https://user-images.githubusercontent.com/83258849/174642595-3dedee4a-c3f6-4164-83d7-8c2b71c1f29c.png)

For Python2.7, we can use `uncompyle6`. We see that it decompiles it nicely.

![](https://user-images.githubusercontent.com/83258849/174642733-956014cc-62d3-47d2-9fe2-e1ea5797e43c.png)

> Note, some of you might have trouble installing uncompyle6 or decompyle3. I faced similar issues and managed to get it to work. If you need help, just give me a dm on discord :)

[main.py](../../../STANDCON\_2022/Reverse/Want%20a%20byte)

```python
import sys
from random import randint
import utils



def generate_random_key(size = 16):
    iter_len = len(utils.key_space) - 1
    rand_val = ""

    utils.patch_keyspace()

    for i in range(size):
        rand_val += utils.key_space[randint(0, iter_len)]

    return rand_val



def derive_key(rand_key):
    sub_key_1 = ""
    sub_key_2 = ""
    k1 = ["n","o","t","_","s","o","_","e","a","s","y","_","p","a","l"]
    k2 = ["t","r","y","_","h","a","r","d","_","t","o","_","w","i","n"]
    k3 = 10
    master_key = ""

    for i in range(len(rand_key)):
        if i & 1 == 0:
            sub_key_1 += rand_key[i]
        else:
            sub_key_2 += rand_key[i]

    for k1, k2 in zip(sub_key_1, sub_key_2):
        master_key += chr((ord(k1) ^ ord(k2)) ^ (ord(k1)))

    return master_key


def mask_master_key(master_key, mask):
    bin_val = ""
    mask_val = ""

    for i in master_key:
        bin_val += ("0"*8 + bin(ord(i))[2:])[-8:]

    for i in mask:
        mask_val += ("0"*8 + bin(ord(i))[2:])[-8:]

    bin_val_len = len(bin_val)
    mask_val_len = len(mask_val)
    mask_val = mask_val[bin_val_len % mask_val_len:] + mask_val * (bin_val_len // mask_val_len)
    v = ""

    for b0, b1 in zip(bin_val, mask_val):
        v += str(int(b0) ^ int(b1))

    vlen = len(v)

    rem = ""

    if vlen%8:
        rem = chr(int(v[:vlen%8], 2))

    for i in range(vlen//8):
        rem += chr(int(v[i*8:i*8+8], 2))

    return rem



flag = raw_input("Enter flag: ").strip()


if len(flag) == 50:
    utils.patch_keyspace()

if not flag.startswith("STANDCON22{") or not flag.endswith("}"):
    print("Try again :/")
    sys.exit(-1)


try:
    assert((mask_master_key(derive_key(generate_random_key(40)), utils.generate_mask(flag[11:-1]))) == ">\x13R\x17>\x11\x18V\tQ\x0f>\x03\x18\x15R\x02Q\x05R")
    print("Correct flag!")
except Exception as e:
    print("Incorrect flag!")
```

[utils.pyc](../../../STANDCON\_2022/Reverse/Want%20a%20byte)

```python
import hashlib
from string import printable
key_space = printable

def patch_keyspace():
    global key_space
    key_space = 'a' * len(key_space)


def generate_mask(inp):
    mod_inp = (lambda x: x.split()[0])(inp)
    _mod_inp = ''
    for i in mod_inp:
        _mod_inp += chr((ord(i) ^ 10 + ord(i)) * 3 % 120 + 5)

    mod_inp_ = hashlib.md5(_mod_inp.encode('utf-8')).hexdigest()
    return mod_inp
```

In [main.py](../../../STANDCON\_2022/Reverse/Want%20a%20byte) I noticed that the code in the `derive_key` and `generate_random_key` functions are pretty much static.

So printing out `derive_key(generate_random_key(40))` would give us the same output everytime, which is 'a'\*20.

![](https://user-images.githubusercontent.com/83258849/174644594-33417997-2be3-4692-a993-56f1a7ea3f49.png)

We can see that it grabs the characters within the brackets of the flag `STANDCON22{}` and performs a check against it, where the output would have to be `">\x13R\x17>\x11\x18V\tQ\x0f>\x03\x18\x15R\x02Q\x05R"`

```python
assert((mask_master_key(derive_key(generate_random_key(40)), utils.generate_mask(flag[11:-1]))) == ">\x13R\x17>\x11\x18V\tQ\x0f>\x03\x18\x15R\x02Q\x05R")
```

What the `utils.generate_mask` function does is pretty simple after you try to run it with your own input. You don't really have to reverse engineer the code in the function.

It just returns whatever you feed it before a space.

> Though, if you did try to reverse it, you would see that it seems like the function is returning an md5 hash value. So how can it return the string itself? If you look carefully at the naming of the variable assigned to the hash, it is different from the one that the function returns.

> `mod_inp_` and `mod_inp`

> I fell for this sly trickery as well.

![image](https://user-images.githubusercontent.com/83258849/174645724-10f8f052-53f5-4d49-886f-bb59d2694956.png)

The `mask_master_key` function in short, basically just converts each character of the `master_key` ('a'\*20) and the flag (within the brackets) into bits, and performs an xor operation between the two, returning the result.

This is just a simple xor operation, you don't have to split them into bits to perform an xor like that.

Because xor can be reversed if you know what the result is and what the original value got xored with, we can just use the expected output and xor each character with 'a' to retrieve the original value, the flag.

## Solve.py

```python
#!/usr/bin/env python3

key = b">\x13R\x17>\x11\x18V\tQ\x0f>\x03\x18\x15R\x02Q\x05R"

flag = ""
for c in key:
	flag += chr(c^ord('a'))

print(flag)
```

Flag: `STANDCON22{_r3v_py7h0n_byt3c0d3}`
