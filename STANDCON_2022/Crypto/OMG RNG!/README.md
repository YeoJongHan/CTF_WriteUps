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
- Use `Chinese Remainder Theorem` on all shares.
- Use result from `CRT` and perform `mod m0` to get long value of `FLAG`.
- Stonks
#
### Analysis
