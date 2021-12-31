# Description
> What have you done to Greet0r??? >:(

> His best friend Descript0r is extra mad at you now. Becareful I heard he knows kung-fd!

> Author: **Carl Voller**

> `nc descript0r-0verfl0w.nypinfsecctf.tk 8010`

We are given a copy of the binary `Descript0r` to help us in the challenge.

_Disclaimer: I only managed to solve this challenge locally after the CTF ended, so I couldn't get the flag._
## The Challenge

This is related to the first pwn challenge `Meet Greet0r`.

Running the binary, it just runs normally without any issues.

We can use `ghidra` to help us decompile the binary https://ghidra-sre.org/

Make sure to choose the `Descript0r` binary and check the `Decompiler Parameter ID` option.

![image](https://user-images.githubusercontent.com/83258849/147810867-47217bf8-f3ad-4b25-82a6-ddac58af3367.png)

Under the `Symbol Tree` on the left pane of `ghidra`, open up `Functions` and choose to view the `main` function as it is where our code starts.

![image](https://user-images.githubusercontent.com/83258849/147810921-80e19f03-721b-4784-bbaf-f23e5eb00128.png)

On the right pane, we can see the decompiled code of the `main` function.

![image](https://user-images.githubusercontent.com/83258849/147811084-eca3e440-004a-419f-b115-c771ff762333.png)

Looks like the flag will be printed out if our `local_18` variable is equal to `0xcafebabe`. We can also see that the `local_18` variable is defined above in the `main` function as well. This is exactly like the `Meet Greet0r` challenge. You can refer to it for more explanation on how to overwrite a local variable on the stack through buffer overflow. We will do the same things like we did in the `Meet Greet0r` challenge :)


