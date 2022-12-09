# Asmuth Shares

## Description

> Asmuth wants to share something with you!

* [chal.py](../../../challenge\_files/STANDCON\_2022/Crypto/Asmuth%20Shares/challenge/chal.py)
* [out.txt](../../../challenge\_files/STANDCON\_2022/Crypto/Asmuth%20Shares/challenge/out.txt)

### TL;DR

* Use `Chinese Remainder Theorem` on all shares.
* Use result from `CRT` and perform `mod m0` to get long value of `FLAG`.
* Stonks

## Solution

### Analysis

{% tabs %}
{% tab title="out.txt" %}
```
Public (m0): 0x61f42f24878101c5186ec677cd44a2b14071b9a69260a026fb385482123f2bd647f74e8c569d3cad1c2d48ad6da58ceddd021c5d

Share 0 (s0, m1): (0x60ec3bb546f5905293052cc6154d632942ef447f3983665f34651637c34c384970abf40095368ffd426f5139ec3d1e07a868a830, 0x6307ff90da6fa375ccf1803b158219da8b9e44fb6859c2f18ce7095584136dfd805a5ac4ecea326c10863ed6e2e39ac82abc9c49)
Share 1 (s1, m2): (0x58675225153f997cd4f4d5bcc0ec9febf60ca7e7aa1759ae8a7037ad0dc4ce45ec79e49c3a1f8bb011adadc57e7d8a39bb845cad, 0x6cdc758a8d408a4ef39acd33f9677c268d685c9ddb3276fb970ad6fe2ebe549daace27fd7b05ca495ba3fe7fef9f9bbd23baf44d)
Share 2 (s2, m3): (0x3d045f39ea1b2f9a5486b16fef3b9a99fd68de9d2d9235c14b6254d3dedb40f7bc8f2087de7a111671426d83b6c9f1709ab90d89, 0x727113b40e9c974febb4e7cb2952083f96a97d1b17093963ee7c474fe780f5bf31241b540470c949593b363ca2c84d73584eb2f3)
Share 3 (s3, m4): (0x3e27c86088d7c7725814c9efe17909c408a1ddca3f0397c81d142b03d6329ef30941b558f22dc8bc20e752e4a6088a7067e76565, 0x7739b291c0ba89eec860dc8a6b018acb5d05d879504285a079b2785edac2cd543c6a86589071835d74f63524952910944b0977e7)
```
{% endtab %}

{% tab title="chal.py" %}
```python
from Crypto.Util.number import getPrime, getRandomRange, bytes_to_long

FLAG = bytes_to_long(open("flag.txt", "rb").read())
N = FLAG.bit_length() + 2**7

m = sorted([ getPrime(N) for _ in range(5) ])
share = []

while ((m[1]*m[2]*m[3] < m[0]*m[3]*m[4]) and m[4]<m[3]):
	m[4] = getPrime(N)

M = m[1]*m[2]
alpha = getRandomRange(2, M)
k = 4

for i in range(k):
    s = (FLAG + alpha*m[0]) % m[i+1]
    share.append(s)

with open("out.txt", 'w') as f:
    f.write(f"Public (m0): {hex(m[0])}\n\n")

    for i in range(len(share)):
        f.write(f"Share {i} (s{i}, m{i+1}): ({hex(share[i])}, {hex(m[i+1])})\n")
```
{% endtab %}
{% endtabs %}

We are given the values of quite a few variables in the [out.txt](../../../challenge\_files/STANDCON\_2022/Crypto/Asmuth%20Shares/challenge/out.txt) file.

Reading the code for [chal.py](../../../challenge\_files/STANDCON\_2022/Crypto/Asmuth%20Shares/challenge/chal.py), we can see that it encrypts the flag with the use of nearly all values given in [out.txt](../../../challenge\_files/STANDCON\_2022/Crypto/Asmuth%20Shares/challenge/out.txt). Should be fairly simple to decrypt the flag.

#### Analyzing chal.py

The flag is first converted into a `long integer`. Then a value `N` is assigned `<number of bits of the flag> + 2**7`. It then randomly generates 5 different prime numbers with `N` bits and stores them into a sorted list `m`.

```python
FLAG = bytes_to_long(open("flag.txt", "rb").read())
N = FLAG.bit_length() + 2**7

m = sorted([ getPrime(N) for _ in range(5) ])
```

Then is just loops through until `m[4]` is a prime number such that `m[0]*m[3]*m[4]` is more than `m[1]*m[2]*m[3]`, and `m[4]` is more than `m[3]`. This part isn't really important.

```python
while ((m[1]*m[2]*m[3] < m[0]*m[3]*m[4]) and m[4]<m[3]):
	m[4] = getPrime(N)
```

It then generates a number and assigns it to the variable `alpha`. We can't really find the value of `alpha` as it is a random number and `M` is a pretty large number.

```python
M = m[1]*m[2]
alpha = getRandomRange(2, M)
k = 4
```

4 values are then generated and stored in `s`. This is the important part of the encryption. Last few lines are just to write out the values to [out.txt](../../../challenge\_files/STANDCON\_2022/Crypto/Asmuth%20Shares/challenge/out.txt).

```python
for i in range(k):
    s = (FLAG + alpha*m[0]) % m[i+1]
    share.append(s)
```

From this part of the code, we have all the values of every variable except for `alpha`.

Take note that the portion `s = (FLAG + alpha*m[0]) % m[i+1]` repeats 4 times, with different `s` results, using `m[1]` to `m[4]` as the modulus at each iteration, and `(FLAG + alpha*m[0])` being the same at each iteration (the number being modulo is the same each time).

So we can form 4 equations given the values we got from out.txt:

* `s0 = (FLAG + alpha*m[0]) % m1`
* `s1 = (FLAG + alpha*m[0]) % m2`
* `s2 = (FLAG + alpha*m[0]) % m3`
* `s3 = (FLAG + alpha*m[0]) % m4`

If you are unfamiliar with these equations, we can basically solve for the value of `(FLAG + alpha*m[0])` using the [Chinese Remainder Theorem (CRT)](https://en.wikipedia.org/wiki/Chinese\_remainder\_theorem).

Since I haven't officially study `Number Theory` and I mostly read about these algorithms online, I may not be the best at explaining it. You can search on [Youtube](https://www.youtube.com) or [Wikipedia](https://www.wikipedia.com) on how it works.

We can easily implement `CRT` in Python by doing so:

```python
from sympy.ntheory.modular import crt
x = crt(mod,res)[0] 	# mod and res has to be lists
```

We can substitute `mod` for a list containing `m1`,`m2`,`m3`,`m4`.

We can substitute `res` for a list containing `s0`,`s1`,`s2`,`s3`.

With this, we retrieved the value of `(FLAG + alpha*m[0])`.

To get value of `FLAG`, notice how `m0` is an extremely large number and how it is multiplied to `alpha`. Thus, we can get rid of the `alpha*m[0]` part just by performing `mod m0` on the value!

```python
(FLAG + alpha*m0) % m0 = FLAG % m0 + (alpha*m0) % m0
(alpha*m0) % m0 = 0
FLAG % m0 = FLAG       # Since it is most likely that FLAG < m0 as m0 is an extremely large number
# Therefore
(FLAG + alpha*m0) % m0 = FLAG
```

### Solve.py

```python
#!/usr/bin/env python3

from sympy.ntheory.modular import crt
from Crypto.Util.number import long_to_bytes

s0 = 0x60ec3bb546f5905293052cc6154d632942ef447f3983665f34651637c34c384970abf40095368ffd426f5139ec3d1e07a868a830
m1 = 0x6307ff90da6fa375ccf1803b158219da8b9e44fb6859c2f18ce7095584136dfd805a5ac4ecea326c10863ed6e2e39ac82abc9c49

s1 = 0x58675225153f997cd4f4d5bcc0ec9febf60ca7e7aa1759ae8a7037ad0dc4ce45ec79e49c3a1f8bb011adadc57e7d8a39bb845cad
m2 = 0x6cdc758a8d408a4ef39acd33f9677c268d685c9ddb3276fb970ad6fe2ebe549daace27fd7b05ca495ba3fe7fef9f9bbd23baf44d

s2 = 0x3d045f39ea1b2f9a5486b16fef3b9a99fd68de9d2d9235c14b6254d3dedb40f7bc8f2087de7a111671426d83b6c9f1709ab90d89
m3 = 0x727113b40e9c974febb4e7cb2952083f96a97d1b17093963ee7c474fe780f5bf31241b540470c949593b363ca2c84d73584eb2f3

s3 = 0x3e27c86088d7c7725814c9efe17909c408a1ddca3f0397c81d142b03d6329ef30941b558f22dc8bc20e752e4a6088a7067e76565
m4 = 0x7739b291c0ba89eec860dc8a6b018acb5d05d879504285a079b2785edac2cd543c6a86589071835d74f63524952910944b0977e7

m0 = 0x61f42f24878101c5186ec677cd44a2b14071b9a69260a026fb385482123f2bd647f74e8c569d3cad1c2d48ad6da58ceddd021c5d

mod = [m1,m2,m3,m4]
res = [s0,s1,s2,s3]

x = crt(mod,res)[0]

print(long_to_bytes(x%m0))

# flag: STANDCON22{CRT_F0r_7h3_W1n_38a9c56b}
```
