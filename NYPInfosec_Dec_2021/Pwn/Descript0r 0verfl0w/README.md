# Description
> What have you done to Greet0r??? >:(

> His best friend Descript0r is extra mad at you now. Becareful I heard he knows kung-fd!

> Author: **Carl Voller**

> `nc descript0r-0verfl0w.nypinfsecctf.tk 8010`

We are given a copy of the binary `Descript0r` to help us in the challenge.
## The Challenge
This is related to the first pwn challenge `Meet Greet0r`.

Running the binary, it just runs normally without any issues.

We can use `ghidra` to help us decompile the binary https://ghidra-sre.org/

Make sure to choose the `Descript0r` binary and check the `Decompiler Parameter ID` option.

![image](https://user-images.githubusercontent.com/83258849/147810867-47217bf8-f3ad-4b25-82a6-ddac58af3367.png)

Under the `Symbol Tree` on the left pane of `ghidra`, open up `Functions` and choose to view the `main` function as it is where our code starts.

![image](https://user-images.githubusercontent.com/83258849/147810921-80e19f03-721b-4784-bbaf-f23e5eb00128.png)

On the right pane, we can see the decompiled code of the `main` function.

![image](https://user-images.githubusercontent.com/83258849/147810947-e3204334-f27c-4d41-875f-b78a6a6d413f.png)
