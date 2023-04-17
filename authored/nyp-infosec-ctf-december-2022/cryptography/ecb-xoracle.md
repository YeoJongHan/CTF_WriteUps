# ECB Xoracle

| Difficulty | Points |
| ---------- | ------ |
| Easy       | 150    |

## Description

> I implemented an additional step in my encryption/decryption service and declare its name as "Xoracle". It should be more secure, right?

> 34.126.175.135:8009

{% file src="../../../.gitbook/assets/chall (2).py" %}

## Solution

### TL;DR

1. Notice that each character of the flag XORs every 16 bytes (1 block) of your input before the encryption.
2. Since the algorithm uses ECB, and we know the first few characters of the flag, we can bruteforce the characters of the flag one by one.
3. We know the character is correct when the encrypted bytes in a block are the same as the encrypted bytes in the previous block.

### Analysis

{% tabs %}
{% tab title="chall.py" %}
```python
#!/usr/bin/env python3

from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from itertools import cycle
from secret import flag

def xor(msg:bytes,key:bytes)->bytes:
  return ''.join([chr(a^b) for a,b in zip(msg,cycle(key))]).encode('utf-8')

class My_ECB:
  def __init__(self):
    self.__key = get_random_bytes(16)
    self.__cipher = AES.new(self.__key, AES.MODE_ECB)
  
  def encrypt(self, data:str,iv:bytes)->str:
    if len(data)%16>0:
      data = pad(data.encode('utf-8'), AES.block_size)
    else:
      data = data.encode()
    ct_1 = self.xor_ecb(data,iv)
    ct_bytes = self.__cipher.encrypt(ct_1)
    ct = b64encode(ct_bytes).decode('utf-8')
    return ct

  def decrypt(self,msg:str,iv:bytes)->str:
    try:
      msg = b64decode(msg.encode('utf-8'))
      ct_1 = self.__cipher.decrypt(msg)
    except:
      return None
    data = self.xor_ecb(ct_1,iv)
    try:
      pt = unpad(data,AES.block_size).decode('utf-8')
    except:
      pt = data.decode('utf-8')
    return pt

  def xor_ecb(self,data:bytes,key:bytes)->bytes:
    blocks = [data[i:i+16] for i in range(0,len(data),16)]
    result = b''
    for block,val in zip(blocks,cycle(list(key))):
      result += xor(block,chr(val).encode('utf-8'))
    assert len(result) == len(data)
    return result


if __name__ == "__main__":
  assert len(flag) == 16

  print('''
$$\   $$\  $$$$$$\  $$$$$$$\   $$$$$$\   $$$$$$\  $$\       $$$$$$$$\ 
$$ |  $$ |$$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$ |      $$  _____|
\$$\ $$  |$$ /  $$ |$$ |  $$ |$$ /  $$ |$$ /  \__|$$ |      $$ |      
 \$$$$  / $$ |  $$ |$$$$$$$  |$$$$$$$$ |$$ |      $$ |      $$$$$\    
 $$  $$<  $$ |  $$ |$$  __$$< $$  __$$ |$$ |      $$ |      $$  __|   
$$  /\$$\ $$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$\ $$ |      $$ |      
$$ /  $$ | $$$$$$  |$$ |  $$ |$$ |  $$ |\$$$$$$  |$$$$$$$$\ $$$$$$$$\ 
\__|  \__| \______/ \__|  \__|\__|  \__| \______/ \________|\________|
  ''')
  print('A service to encrypt and decrypt any strings for free, but you can only decrypt once per encryption!\n')
  while True:
    e = My_ECB()
    data = str(input("Enter a string to encrypt (-1): "))
    if data == '-1':
      break
    result = e.encrypt(data,flag)
    print(">>>",result)
    data = str(input("Enter a base64 encoded ciphertext (-1): "))
    if data == '-1':
      break
    result = e.decrypt(data,flag)
    if result == None:
      print("No no, that ain't right.")
    else:
      print(">>>",result)

```
{% endtab %}
{% endtabs %}

Following the path of the `flag`, we can see the flow as follows:

1. `len(flag) == 16`
2. `result = e.encrypt(data,flag)`
3. `ct_1 = self.xor_ecb(data,flag)`
4.  `blocks = [data[i:i+16] for i in range(0,len(data),16)]`

    `for block,val in zip(blocks,cycle(list(key))):`

    &#x20;   `result += xor(block,chr(val).encode('utf-8'))`
5.  `def xor(msg:bytes,key:bytes)->bytes:`

    &#x20;   `return ''.join([chr(a^b) for a,b in zip(msg,cycle(key))]).encode('utf-8')`

Focusing on the 4th point, we see that each character of the flag is XORed with each block of the input data, where each block is 16 bytes.

Now focusing on the 5th point, we see that each character is provided to a `cycle` function, which basically copies that value until it is the same length as as each block (`zip(msg,cycle(key))`).

Since we know the flag format is NYP{...}, meaning if we input 'A'\*16 + 'B'\*16 + 'C'\*16, this would be the following result of the XOR:

| AAAAAAAAAAAAAAAA  | BBBBBBBBBBBBBBBB  | CCCCCCCCCCCCCCCC  |
| ----------------- | ----------------- | ----------------- |
| XOR               | XOR               | XOR               |
| NNNNNNNNNNNNNNNN  | YYYYYYYYYYYYYYYY  | PPPPPPPPPPPPPPPP  |
| ECB Encrypt Block | ECB Encrypt Block | ECB Encrypt Block |
| CT\_BLOCK\_1      | CT\_BLOCK\_2      | CT\_BLOCK\_3      |

Now, we can utilize a feature of XOR, where if you XOR a character by itself, it would return 0 (e.g. N^N = 0).

Since xor(('N'\*16),('N'\*16)) == 0, and xor(('Y'\*16),('Y'\*16)) == 0, if ECB encryption is performed on both blocks of 0, we would get the same Ciphertext output since it is using ECB Encryption algorithm.

{% hint style="info" %}
ECB Encryption:

![](<../../../.gitbook/assets/image (12) (1) (1).png>)
{% endhint %}

So we can bruteforce each character of the flag in sizes of 16 bytes, and check if that 16 byte CT block output is equal to the one where 0 is encrypted.

{% hint style="warning" %}
For those who are confused, here is an example:

Let's say if we input 'N'\*16 for the first block and got the output CT as 'ABCDEFGHIJKLMNOP', then if we give 'N'\*16 + 'Y'\*16 as the input to encrypt, it should return us 'ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP' (notice first and last 16 bytes are the same).

And so if we provide 'N'\*16+'Y'\*16+'P'\*16+'{'\*16+'A'\*16, if the CT output is 'ABCDEFGHIJKLMNOP...ABCDEFGHIJKLMNOP', where the last 16 bytes are equal to the first 16 bytes of CT, then we know that the character 'A' is correct and our flag would be NYP{A...}.
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (18) (1).png" alt=""><figcaption><p>Running bruteforce solve script</p></figcaption></figure>

{% tabs %}
{% tab title="solve.py" %}
```python
from pwn import *
import base64, string

def encrypt(payload):
    global p
    p.recvuntil(b': ')
    p.clean()
    p.sendline(payload.encode())
    p.recvuntil(b'>>> ')
    return p.recvline().strip()

url,port = "34.126.175.135",8009

p = remote(url,port)
flag = 'NYP{'

chars = '''0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'''

while len(flag) < 16:
    for c in chars:
        test = ''.join([x*16 for x in flag + c])
        res = encrypt(test)
        result = base64.b64decode(res)
        blocks = [result[x:x+16] for x in range(0,len(result),16)]
        p.recvuntil(b': ')
        p.clean()
        p.sendline(res)
        if blocks[0] == blocks[-1]:
            flag += c
            print(flag)
            break
print("Found flag:",flag)            

p.close()

```
{% endtab %}
{% endtabs %}

