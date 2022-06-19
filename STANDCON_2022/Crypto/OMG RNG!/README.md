# OMG RNG!
## Description
> Gifts for everyone!

> `nc lab-1.ctf.standcon.n0h4ts.com 7903`

- [chal.py](https://github.com/YeoJongHan/CTF_WriteUps/blob/main/STANDCON_2022/Crypto/OMG%20RNG!/challenge/chal.py)

### Overview
Starting an instance and connecting to the server, the server would run [chal.py](https://github.com/YeoJongHan/CTF_WriteUps/blob/main/STANDCON_2022/Crypto/OMG%20RNG!/challenge/chal.py) and send you `gifts` and a `secret` containing the flag that is encrypted.

We have to figure out a way to decrypt the `secret` retrieved from the server using the `gifts`.

## Solution
### TL;DR
- Use `gcd` to find value of `m`
- Get the previous state by solving `linear congruence` between `m` and first `gift` received.
- Get previous state until it reaches the first state.
- Perform `XOR` of `secret` with first 2 states.
- Got flag
#
### Analysis
[chal.py](https://github.com/YeoJongHan/CTF_WriteUps/blob/main/STANDCON_2022/Crypto/OMG%20RNG!/challenge/chal.py)
``` python
from Crypto.Util.number import bytes_to_long, getRandomRange

FLAG = bytes_to_long(open("flag.txt", "rb").read())

class MLFG():
    def __init__(self):
        self.m = getRandomRange(2, 2**300)
        self.s0, self.s1 = [getRandomRange(2, self.m-1) for _ in '__']
        self.curr_state = 0
    
    def next(self):
        self.curr_state = (self.s0 * self.s1) % self.m
        self.s0 = self.s1
        self.s1 = self.curr_state
        return self.curr_state


if __name__ == '__main__':
    
    P = MLFG()
    secret = FLAG ^ P.s0 ^ P.s1
    
    [P.next() for _ in range(1337)] # discard some states :p

    for _ in range(5):
        ch = input("\n[1] Get a random gift \n[2] Get Secret! \n\n[?]> ").strip()
        if ch == '1':
            print("\nHere's your gift:", hex(P.next()))
        elif ch == '2':
            print("\nHere's your secret:", hex(secret))
        else:
            exit("\nOops! Invalid input!")
    else:
        exit("\nEnough Gifts!")
```

It's a pretty short code, so let's quickly break it down.

### Analyzing chal.py

The `MLFG` class gets initialized first.

When the `MLFG` class gets initialized, it grabs a large random number and stores it as `m` in the class. Then it randomly generates 2 other numbers smaller than `m`, and stores it in `s0` and `s1` in the class. `curr_state` is then assigned with the value `0`.
``` python
class MLFG():
    def __init__(self):
        self.m = getRandomRange(2, 2**300)
        self.s0, self.s1 = [getRandomRange(2, self.m-1) for _ in '__']
        self.curr_state = 0
```
The `next()` function is pretty self explanatory.
``` python
def next(self):
        self.curr_state = (self.s0 * self.s1) % self.m
        self.s0 = self.s1
        self.s1 = self.curr_state
        return self.curr_state
```

Searching up `MLFG`, it stands for `Multiplicative Lagged Fibonacci Generator`. I tried to search for any writeups on such challenges but couldn't find any. The key takeaway from looking it up is that this algorithm is a `Pseudo-Random Number Generator` (PRNG).

According to the `MLFG` class, we can see how it performs as a `PRNG`:
1. It first generates a random number as a modulus (`m`)
2. It then generates 2 random numbers to start with (`s0` and `s1`)
3. To get a random value, it multiplies both `s0` and `s1` and mod `m` and returns it (this is what makes it `Multiplicative` as the name of the class suggest). So `curr_state` would be your random value.
4. It then stores the value of `s1` into `s0`, and the current value (`curr_state`) generated into `s1` (this is what makes it `Lagged Fibonacci`).

Here are some images to help you visualize it. (assume f() is a function `(self.s0 * self.s1) % self.m`. Note that the numbers in the picture are just an example.)

<img src="https://user-images.githubusercontent.com/83258849/174485595-ae536c72-359a-456f-914a-86a454dccfbc.png" width="200" height="150"><img src="https://user-images.githubusercontent.com/83258849/174485821-a24afa57-2846-40eb-8900-8a80612ecda0.png" width="200" height="150"><img src="https://user-images.githubusercontent.com/83258849/174485902-356abae7-cb27-4d07-a4a8-0e2c6e5019c6.png" width="200" height="150">

See why it is related to `Fibonacci`?

Now, the last few lines of code is to produce the `secret` where the flag is encrypted through `xor`. We can easily find the flag if we find the values it got xored with (goal is to find the original value of `s0` and `s1`).

You then get to retrieve the value of `secret` and the next few random values generated.
``` python
P = MLFG()
    secret = FLAG ^ P.s0 ^ P.s1
    
    [P.next() for _ in range(1337)] # discard some states :p

    for _ in range(5):
        ch = input("\n[1] Get a random gift \n[2] Get Secret! \n\n[?]> ").strip()
        if ch == '1':
            print("\nHere's your gift:", hex(P.next()))
        elif ch == '2':
            print("\nHere's your secret:", hex(secret))
        else:
            exit("\nOops! Invalid input!")
    else:
        exit("\nEnough Gifts!")
```
### Finding value of 'm'
We will first have to grab the next few states of `MLFG`. I went to grab 4 states and then the `secret`.

We will be focusing on this line of code:
``` python
self.curr_state = (self.s0 * self.s1) % self.m
self.s0 = self.s1
self.s1 = self.curr_state
```
Since we have grabbed 4 consecutive states of `MLFG`, we have something like this:
- `gift0` = (`unknown s0` * `unknown s1`) % `m`
- `gift1` = (`unknown s1` * `gift0`) % `m`
- `gift2` = (`gift0` * `gift1`) % `m`
- `gift3` = (`gift1` * `gift2`) % `m`

One thing to note, modulus equations can also be expressed in another way that is true if you think about it:
> (xy mod m = z) === (xy - n<sub>1</sub>m = z), where n<sub>1</sub> is a random integer

Similarly,
>(gift2 = (gift0 * gift1) % m) === (gift2 = (gift0 * gift1) - n<sub>1</sub>m)

By rearranging the equation...
> (gift0 * gift1) - gift2 = n<sub>1</sub>m

We then have the following equations...
> (gift0 * gift1) - gift2 = n<sub>1</sub>m

> (gift1 * gift2) - gift3 = n<sub>2</sub>m

So now we have n<sub>1</sub>m and n<sub>2</sub>m, we can find the value of `m` by finding the `gcd` of both of them since `m` would be larger than n<sub>1</sub> and n<sub>2</sub>!

### m acquired!
#
### Finding previous state
Let's focus on this equation as we want to find the previous state:
- `gift1` = (`unknown s1` * `gift0`) % `m`

We basically have the value of everything except for the previous state (`unknown s1`)

I had a little trouble solving this due to my lack of knowledge on `modular arithmetic`, but searching it up gives us something called [Linear Congruence](https://www.intmath.com/blog/mathematics/how-to-solve-linear-congruences-12539#:~:text=Generally%2C%20a%20linear%20congruence%20is,%3D%20x0%20(mod%20m).). The `linear congruence` problem is to find the value of `X` given the equation `aX (mod m) = b`, which is exactly what we were looking for!

I managed to find and use a `linear congruence` function implemented in Python [https://stackoverflow.com/questions/48252234/how-to-solve-a-congruence-system-in-python](https://stackoverflow.com/questions/48252234/how-to-solve-a-congruence-system-in-python).

Now we are able to find the previous state! To find previous state of the previous state, we will just have to use the value of the previous state we got.

Example:
``` python
gift1 = (unknown s1 * gift0) % m
# We have m, gift0, and gift1. Use linear congruence to find 'unknown s1'
```

```
gift0 = (unknown s0 * unknown s1) % m
# We have m, gift0, and 'unknown s1'. Use linear congruence to find 'unknown s0'
```

```
unknown s1 = (prev prev state * unknown s0) % m
# We have m, 'unknown s1', and 'unknown s0'. Use linear congruence to find 'prev prev state'
```

We can then just iterate over until we find the flag!

### Solve.py
``` python
#!/usr/bin/env python3

from pwn import *
from Crypto.Util.number import long_to_bytes

# You dont have to use extended euclidean algorithm to find gcd
def extended_gcd(a: int, b: int) -> int:
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x

# aX = b (mod m)
def linear_congruence(a,b,m):
	if b == 0:
		return 0

	if a < 0:
		a = -a
		b = -b

	b %= m
	while a > m:
		a -= m
	return (m * linear_congruence(m, -b, a) + b) // a

server = "lab-1.ctf.standcon.n0h4ts.com"
port = 10172
p = remote(server,port)

gifts = []
for _ in range(4):
	p.clean()
	p.sendline(b'1')
	p.recvuntil(b"Here's your gift: ")
	gifts.append(int(p.recvline().strip().decode(),16))
print("Gifts:",gifts)

p.clean()
p.sendline(b'2')
p.recvuntil(b"Here's your secret: ")
secret = int(p.recvline().strip().decode(),16)

print("Secret:",secret)
p.close()

phi1 = ((gifts[0] * gifts[1]) - gifts[2])
phi2 = ((gifts[1] * gifts[2]) - gifts[3])

gcd,x,y = extended_gcd(phi1,phi2)
m = gcd
print("m:",m)
r0 = gifts[0]
r1 = gifts[1]

l = []

for _ in range(1345):
	tmp = r0
	r0 = linear_congruence(r0,r1,m)
	l.append(r0)
	r1 = tmp
	test = long_to_bytes(secret^r0^r1)
	if b"STANDCON" in test:
		print("\n\nFlag:",test.decode())
		exit()
	print('.',end='')

# Check:
# l = l[::-1]
# for _ in range(len(l)):
# 	curr_state = (r0 * r1) % m
# 	r0 = r1
# 	r1 = curr_state
# print(curr_state)
```
