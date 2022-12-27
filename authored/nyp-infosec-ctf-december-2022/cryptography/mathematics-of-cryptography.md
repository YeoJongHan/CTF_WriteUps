# Mathematics of Cryptography

| Difficulty | Points |
| ---------- | ------ |
| Easy       | 150    |

## Description

> The Defenders heard that there are some Math legends among us and have reached out for assistance in breaking one of the Uprisers' security defenses.

{% file src="../../../.gitbook/assets/chall (3).py" %}

{% file src="../../../.gitbook/assets/output.txt" %}

## Solution

### TL;DR

1. Utilize values of `n`, `p-q`, and `(p^3-q^3)` to find the value of `p` or `phi` through solving a series of algebraic equations.

### Analysis

{% tabs %}
{% tab title="chall.py" %}
```python
#!/usr/bin/env python3

from Crypto.Util.number import getPrime, getRandomInteger, bytes_to_long
import math
from secret import flag

p,q = [getPrime(512) for _ in range(2)]
n = p*q
e = 65537

a = getRandomInteger(128)
m = bytes_to_long(flag)
ct = pow(m,e,n)

print(f"{p-q=}")
print(f"{pow(p,3)-pow(q,3)=}")
print(f"{n=}")
print(f"{ct=}")
```
{% endtab %}

{% tab title="output.txt" %}
```
p-q=-1305235648860840853683949458831305072763230973669829177960178482866452800364412721111763583069321978987148627466498224410781024187725838888479326409184744
pow(p,3)-pow(q,3)=-465514652595610856880453636545438331400010973790168791066069161352239209188533132121982942661849199245018660968880021999471046367873763759524854675286821508038418401864765726491449185192253500864628518550804809046508686959255535195714941766727484090297166583454871187745735758463441767587210583432967693381451227261083381147367649535205516682361917227931630894904749876510765825586785760034509104564737258991404912289408762611694496702482996518688138500642819128
n=118316055600083929089071669812439032539191357668051889677911602916721340636167359556934591671598570703259986990715914276095866429868571322432308962619799310816435693053230854913872753733501348441234715512020861405241513403795045428404496593692411330352525309662619935495570018411169134102570106958094779439217
ct=64880869410692063175906103028969957878271889970688259195068268235741104167117130794136851712307899764163566653527660540303926093374874865621497088649195483963877573321808998916766978276663044270028514646216644963284229260389738926787740160186040707610308628316701038087132926246223087221028661729121666185863
```
{% endtab %}
{% endtabs %}

We can see that we have very little code to work with, and the values provided are for the ones showed in `output.txt`.

Recall that we need `d` to decrypt the `ct`, where `pt = pow(ct,d,n)`.

{% hint style="info" %}
This [site](https://www.di-mgt.com.au/rsa\_alg.html) provides a recap on how to obtain `d` for decrypting RSA, where I quote:

1. Generate two large random primes, $$p$$ and $$q$$, of approximately equal size such that their product $$n=pq$$ is of the required bit length, e.g. 1024 bits. \[See [note 1](https://www.di-mgt.com.au/rsa\_alg.html#note1)].
2. Compute $$n=pq$$ and $$ϕ=(p−1)(q−1)$$. \[See [note 6](https://www.di-mgt.com.au/rsa\_alg.html#note6)].
3. Choose an integer $$e$$, $$1<e<ϕ$$, such that $$gcd(e,ϕ)=1$$. \[See [note 2](https://www.di-mgt.com.au/rsa\_alg.html#note2)].
4. Compute the secret exponent $$d$$, $$1<d<ϕ$$, such that $$ed≡1modϕ$$. \[See [note 3](https://www.di-mgt.com.au/rsa\_alg.html#note3)].
5. The public key is $$(n,e)$$ and the private key $$(d,p,q)$$. Keep all the values d, p, q and ϕ secret. \[Sometimes the private key is written as $$(n,d)$$ because you need the value of n when using d. Other times we might write the key pair as $$((N,e),d)$$.]
{% endhint %}

Our d also has to be derived from `e` and `phi`, where `phi` would be `(p-1)(q-1)` (refer to the info box above).

Using multiple expansions and substitutions with the values we are given, we can solve for `p` or `phi`.

### Solving for Phi

We can reference this table if there is a need to recap the algebra rules:

<figure><img src="../../../.gitbook/assets/image.png" alt=""><figcaption><p>Basic rules of algebra</p></figcaption></figure>

Focusing on values of `n`, `p-q`, and `(p^3-q^3)`:

<figure><img src="../../../.gitbook/assets/image (3).png" alt=""><figcaption><p>Equations to get phi</p></figcaption></figure>

Now we got `phi` using the values that we have, we can just get `d` using the Euclidean Algorithm and decrypt the ciphertext!

{% tabs %}
{% tab title="solve.py" %}
```python
#!/usr/bin/env python3

from Crypto.Util.number import getPrime, getRandomInteger, bytes_to_long, long_to_bytes
import math
from decimal import Decimal

def isqrt(x):
    """Return the integer part of the square root of x, even for very
    large integer values."""
    if x < 0:
        raise ValueError('square root not defined for negative numbers')
    if x < _1_50:
        return int(math.sqrt(x))  # use math's sqrt() for small parameters
    n = int(x)
    if n <= 1:
        return n  # handle sqrt(0)==0, sqrt(1)==1
    # Make a high initial estimate of the result (a little lower is slower!!!)
    r = 1 << ((n.bit_length() + 1) >> 1)
    while True:
        newr = (r + n // r) >> 1  # next estimate by Newton-Raphson
        if newr >= r:
            return r
        r = newr

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, y
    
_1_50 = 1 << 50  # 2**50 == 1,125,899,906,842,624

pminq=-1305235648860840853683949458831305072763230973669829177960178482866452800364412721111763583069321978987148627466498224410781024187725838888479326409184744
cubepq=-465514652595610856880453636545438331400010973790168791066069161352239209188533132121982942661849199245018660968880021999471046367873763759524854675286821508038418401864765726491449185192253500864628518550804809046508686959255535195714941766727484090297166583454871187745735758463441767587210583432967693381451227261083381147367649535205516682361917227931630894904749876510765825586785760034509104564737258991404912289408762611694496702482996518688138500642819128
n=118316055600083929089071669812439032539191357668051889677911602916721340636167359556934591671598570703259986990715914276095866429868571322432308962619799310816435693053230854913872753733501348441234715512020861405241513403795045428404496593692411330352525309662619935495570018411169134102570106958094779439217
ct=64880869410692063175906103028969957878271889970688259195068268235741104167117130794136851712307899764163566653527660540303926093374874865621497088649195483963877573321808998916766978276663044270028514646216644963284229260389738926787740160186040707610308628316701038087132926246223087221028661729121666185863

e = 65537

aplusbsqr = (cubepq // pminq) + n
pplusq = isqrt(aplusbsqr)
phi = n - (pplusq) + 1

gcd, a, b = egcd(e, phi)
d = a
print(d)
pt = pow(ct, d, n)
print(long_to_bytes(pt))
```
{% endtab %}
{% endtabs %}
