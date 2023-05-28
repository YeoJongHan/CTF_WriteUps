# Broken RSA

## Description

> My friend had a secret message for me. However, he made a mistake when encrypting the message, and now I am unable to decrypt it! Could you decrypt and recover the message for me?

{% file src="../../../.gitbook/assets/BrokenRSA.zip" %}

## TL;DR

* Notice that e = 1616, which makes phi and e not coprime and which is why normal RSA decryption won't work
* Perform `c%p` and `c%q` and RSA decrypt both with their respective `d` and `phi` values
* Use tonelli shank's algorithm to perform square root mod of p and q
* Perform CRT on the values to get original plaintext

## Solution

### Initial Analysis

_If you want to skip the explanation, you can go to_ [_e and phi are not coprime_](broken-rsa.md#e-and-phi-are-not-coprime)_._

{% tabs %}
{% tab title="challenge.py" %}
```python
from Crypto.Util.number import getPrime, bytes_to_long

p = getPrime(512)
q = getPrime(512)
n = p * q
e = 1616

with open("flag.txt", "rb") as f:
    flag = f.read()

c = pow(bytes_to_long(flag), e, n)

with open("output.txt", "w") as f:
    f.write(f"{p=}\n")
    f.write(f"{q=}\n")
    f.write(f"{c=}\n")
    f.write(f"{e=}\n")

```
{% endtab %}

{% tab title="output.txt" %}
```python
p=12745443776097937486523731981184244411822246670344825081786250598280592311994645818017369055015305576625489048312376829887862697232698960303123727339439477
q=6965691623673764963283701881605906791484292250300568740181083332830802480178930748628555885283810920150672372660644966641894191414330596203094237460731853
c=51246606178817027144048790384294344409078205278660263649138314308484271379271492418276059836372460273067275885546317401508060728580046016291398622205239294202483332638706880399609813252751351178753076424449513521022597436767316972137030942140105737604756013333385824335007108113055833516556345445260667314569
e=1616
```
{% endtab %}
{% endtabs %}

Looking at `challenge.py`, everything looks like the usual RSA encryption scheme, except for the value of `e` looking like an **invalid value**. This `e` is the one that makes the RSA decryption difficult to perform.

{% hint style="info" %}
In standard RSA encryption scheme, the public exponent `e` must be an odd number.

If `e` is even, it will most definitely share a common factor with `phi` that is != 1, since `p-1` will be an even number. This means that `e` and `phi` are not coprime.

If `e` and `phi` are not coprime, then there may be multiple decryption exponent `d` that may decrypt the ciphertext.

In this case, normal RSA decryption **will not** work.
{% endhint %}

Luckily, we are given the values of `p` and `q`, as well as the ciphertext `c`.

To determine why normal RSA decryption doesn't work and how to decrypt the ciphertext with this `e` value, we have to first understand the concept behind the RSA cryptosystem: Why and how it works.

### The brilliance behind RSA decryption

We know that RSA encryption goes like this:

<figure><img src="../../../.gitbook/assets/image (1) (5).png" alt=""><figcaption><p>RSA Encryption</p></figcaption></figure>

When decrypting in normal RSA, these steps are performed:

<figure><img src="../../../.gitbook/assets/image (32).png" alt=""><figcaption><p>RSA Decryption</p></figcaption></figure>

But why does this decryption method work?

Firstly, we can rewrite ![](<../../../.gitbook/assets/image (34).png>) into ![](<../../../.gitbook/assets/image (24) (1).png>), where `k` is any finite integer.

We can also rewrite ![](<../../../.gitbook/assets/image (15) (2).png>) into ![](<../../../.gitbook/assets/image (12) (1).png>).

By substituting `ed` into the second `pt` equation, we have ![](<../../../.gitbook/assets/image (35).png>), and thus ![](<../../../.gitbook/assets/image (8) (3).png>).

Using `Euler's Theorem`, we can then get this equation ![](<../../../.gitbook/assets/image (38).png>), and simplifying it gives us out original plaintext! ![](<../../../.gitbook/assets/image (3) (1) (3).png>) (that is if our plaintext < n)

{% hint style="info" %}
What is Euler's Theorem?

[https://t5k.org/glossary/page.php?sort=EulersTheorem#:\~:text=Euler's%20Theorem%20states%20that,%E2%89%A1%201%20(mod%2012).](https://t5k.org/glossary/page.php?sort=EulersTheorem)
{% endhint %}

But this only works if `e` and `phi` are coprime: `gcd(e,phi)=1`.

### e and phi are not coprime

If we check the gcd of the `e` and `phi` we have, we note that `gcd(e,phi)=16` in this case, so that is a problem.

According to `Euler's Theorem`, if `gcd(e,phi)=1`, we will have `ed = 1 + k*phi`.

Since we have `gcd(e,phi)=16`, so we will have `ed = 16 + k*phi`. Following the decryption process as stated above, we will end up with ![](<../../../.gitbook/assets/image (2) (2).png>). Since `m^16` is definitely larger than `n`, we can't take the `16th` root and call it a day.

But wait, there is the **Tonelli-Shanks Algorithm** that can compute the modulus square root of any number, given that the **modulus is a prime**.

### The Tonelli-Shanks Algorithm

We note that our modulus `n = p*q` and is therefore not a prime, so how do we apply this algorithm?

The only primes we have here are `p` and `q`. What if we calculate the ciphertext as a modulus of `p` or `q` instead?

So we can calculate our new ciphertext using the given ciphertext: `ctp = c mod p.` This is equivalent to ![](<../../../.gitbook/assets/image (29).png>) which is simplified to ![](<../../../.gitbook/assets/image (36).png>) (note that `mod n` is gone as `p` is a factor of `n`)

Now we get the `Euler's Totient function` for `p`: `phip = p-1`

<figure><img src="../../../.gitbook/assets/image (9) (1) (2).png" alt=""><figcaption><p>phip</p></figcaption></figure>

Then we calculate `dp = inverse(e,phip)`, then decrypt the ciphertext `ptp = pow(ctp,dp,p)`. Since `gcd(e,phip)=4`, it means we have ![](<../../../.gitbook/assets/image (17).png>). So we have to use **Tonelli** twice to get back our plaintext.

Since `p` is a prime, we can now use **Tonelli-Shanks Algorithm (**[**code**](https://codereview.stackexchange.com/questions/43210/tonelli-shanks-algorithm-implementation-of-prime-modular-square-root)**)**! Let's test this with a test flag of our own:

{% tabs %}
{% tab title="test.py" %}
```python
#!/usr/bin/env python3

from Crypto.Util.number import getPrime, bytes_to_long, inverse, long_to_bytes
from egcd import egcd
from gmpy2 import *
from sympy.ntheory.modular import crt

def legendre_symbol(a, p):
    """
    Legendre symbol
    Define if a is a quadratic residue modulo odd prime
    http://en.wikipedia.org/wiki/Legendre_symbol
    """
    ls = pow(a, (p - 1)//2, p)
    if ls == p - 1:
        return -1
    return ls

def prime_mod_sqrt(a, p):
    """
    Square root modulo prime number
    Solve the equation
        x^2 = a mod p
    and return list of x solution
    http://en.wikipedia.org/wiki/Tonelli-Shanks_algorithm
    """
    a %= p

    # Simple case
    if a == 0:
        return [0]
    if p == 2:
        return [a]

    # Check solution existence on odd prime
    if legendre_symbol(a, p) != 1:
        return []

    # Simple case
    if p % 4 == 3:
        x = pow(a, (p + 1)//4, p)
        return [x, p-x]

    # Factor p-1 on the form q * 2^s (with Q odd)
    q, s = p - 1, 0
    while q % 2 == 0:
        s += 1
        q //= 2

    # Select a z which is a quadratic non resudue modulo p
    z = 1
    while legendre_symbol(z, p) != -1:
        z += 1
    c = pow(z, q, p)

    # Search for a solution
    x = pow(a, (q + 1)//2, p)
    t = pow(a, q, p)
    m = s
    while t != 1:
        # Find the lowest i such that t^(2^i) = 1
        i, e = 0, 2
        for i in range(1, m):
            if pow(t, e, p) == 1:
                break
            e *= 2

        # Update next value to iterate
        b = pow(c, 2**(m - i - 1), p)
        x = (x * b) % p
        t = (t * b * b) % p
        c = (b * b) % p
        m = i

    return [x, p-x]

p=12745443776097937486523731981184244411822246670344825081786250598280592311994645818017369055015305576625489048312376829887862697232698960303123727339439477
q=6965691623673764963283701881605906791484292250300568740181083332830802480178930748628555885283810920150672372660644966641894191414330596203094237460731853
c=51246606178817027144048790384294344409078205278660263649138314308484271379271492418276059836372460273067275885546317401508060728580046016291398622205239294202483332638706880399609813252751351178753076424449513521022597436767316972137030942140105737604756013333385824335007108113055833516556345445260667314569
e=1616
n = p*q

m = bytes_to_long(b'LNC2023{this_is_a_flag}')
c = pow(m,e,n)

ctp = c%p
phip = p-1
dp = inverse(e,phip)
ptp = pow(ctp,dp,p)

r1 = prime_mod_sqrt(ptp,p)
for r in r1:
    r2 = prime_mod_sqrt(r,p)
    for rr in r2:
        print(long_to_bytes(rr))

```
{% endtab %}
{% endtabs %}

<figure><img src="../../../.gitbook/assets/image (27).png" alt=""><figcaption><p>Output</p></figcaption></figure>

We successfully got our own flag!

But if we try this on the ciphertext given to us, it doesn't work...

We note that `p` and `q` are primes each with`512` bits. Because the result we get is `mod p` (![](<../../../.gitbook/assets/image (37).png>)), it is very likely that the original message is > `p`, which is > `512` bits.

We can test this by testing with a flag shorter than `p`, and then testing with a flag longer than `p`.

<figure><img src="../../../.gitbook/assets/image (2) (3).png" alt=""><figcaption><p>m>p</p></figcaption></figure>

And our theory is correct, the original message is most likely > `512` bits...

### Plaintext > 512 bits

So how do we get the plaintext if it is more than `512` bits?

Since we can decrypt using `p` as a modulus, it means we can also decrypt using `q` as a modulus. This means we can end up with 2 different equations with 2 different mods:

<figure><img src="../../../.gitbook/assets/image (22) (1).png" alt=""><figcaption><p>Equations</p></figcaption></figure>

Since `p` and `q` are coprime, the original message is the same but the modulus are different, we can use **Chinese Remainder Theorem (CRT)** to solve for the original message.

## Chinese Remainder Theorem

We can use the `crt` function in the `sympy` python library. We will need to supply a list of mods `[p,q]` and a list of results `[resp,resq]`

{% tabs %}
{% tab title="solve.py" %}
```python
#!/usr/bin/env python3

from Crypto.Util.number import getPrime, bytes_to_long, inverse, long_to_bytes
from egcd import egcd
from gmpy2 import *
from sympy.ntheory.modular import crt

def legendre_symbol(a, p):
    """
    Legendre symbol
    Define if a is a quadratic residue modulo odd prime
    http://en.wikipedia.org/wiki/Legendre_symbol
    """
    ls = pow(a, (p - 1)//2, p)
    if ls == p - 1:
        return -1
    return ls

def prime_mod_sqrt(a, p):
    """
    Square root modulo prime number
    Solve the equation
        x^2 = a mod p
    and return list of x solution
    http://en.wikipedia.org/wiki/Tonelli-Shanks_algorithm
    """
    a %= p

    # Simple case
    if a == 0:
        return [0]
    if p == 2:
        return [a]

    # Check solution existence on odd prime
    if legendre_symbol(a, p) != 1:
        return []

    # Simple case
    if p % 4 == 3:
        x = pow(a, (p + 1)//4, p)
        return [x, p-x]

    # Factor p-1 on the form q * 2^s (with Q odd)
    q, s = p - 1, 0
    while q % 2 == 0:
        s += 1
        q //= 2

    # Select a z which is a quadratic non resudue modulo p
    z = 1
    while legendre_symbol(z, p) != -1:
        z += 1
    c = pow(z, q, p)

    # Search for a solution
    x = pow(a, (q + 1)//2, p)
    t = pow(a, q, p)
    m = s
    while t != 1:
        # Find the lowest i such that t^(2^i) = 1
        i, e = 0, 2
        for i in range(1, m):
            if pow(t, e, p) == 1:
                break
            e *= 2

        # Update next value to iterate
        b = pow(c, 2**(m - i - 1), p)
        x = (x * b) % p
        t = (t * b * b) % p
        c = (b * b) % p
        m = i

    return [x, p-x]

p=12745443776097937486523731981184244411822246670344825081786250598280592311994645818017369055015305576625489048312376829887862697232698960303123727339439477
q=6965691623673764963283701881605906791484292250300568740181083332830802480178930748628555885283810920150672372660644966641894191414330596203094237460731853
c=51246606178817027144048790384294344409078205278660263649138314308484271379271492418276059836372460273067275885546317401508060728580046016291398622205239294202483332638706880399609813252751351178753076424449513521022597436767316972137030942140105737604756013333385824335007108113055833516556345445260667314569
e=1616
n = p*q

phi = (p-1)*(q-1)
d = inverse(e,phi//4)

# m = bytes_to_long(b'LNC2023{this_is_a_very_long_test_flag_tuwinuiwneugnfuhe2hf923hu91fw}')
# print(m)
# ct = pow(m,e,n)
ct = c
ctq = ct % q
ctp = ct % p
phiq = q-1
phip = p-1
dq = inverse(e,phiq)
dp = inverse(e,phip)
ptq = pow(ctq,dq,q)
ptp = pow(ctp,dp,p)

#tonellishank
resq = prime_mod_sqrt(ptq,q)
resq = prime_mod_sqrt(resq[0],q) # guess which num between 2

resp = prime_mod_sqrt(ptp,p)
resp = prime_mod_sqrt(resp[1],p) # guess which num between 2

mod = [p,q]
res = [resp[0],resq[0]]
x = crt(mod,res)[0]
print(long_to_bytes(x))
```
{% endtab %}
{% endtabs %}
