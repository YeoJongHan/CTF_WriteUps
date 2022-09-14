# Descript0r 0verfl0w

## Description

> What have you done to Greet0r??? >:(

> His best friend Descript0r is extra mad at you now. Becareful I heard he knows kung-fd!

> Author: **Carl Voller**

> `nc descript0r-0verfl0w.nypinfsecctf.tk 8010`

{% file src="../../../.gitbook/assets/Descript0r" %}

We are given a copy of the binary `Descript0r` to help us in the challenge.

_I only managed to solve this challenge locally after the CTF ended, so I couldn't get the flag._

## The Challenge

This is related to the first pwn challenge `Meet Greet0r`.

Running the binary, it just runs normally without any issues.

Using `checksec`, we can see that we are in luck as there are no binary checks that would impede our exploit.

![checksec --file Descript0r](https://user-images.githubusercontent.com/83258849/147813776-961b0316-99db-4ef1-99ac-d1e19be7aca5.png)

We can use `ghidra` to help us decompile the binary https://ghidra-sre.org/

Make sure to choose the `Descript0r` binary and check the `Decompiler Parameter ID` option.

![](https://user-images.githubusercontent.com/83258849/147810867-47217bf8-f3ad-4b25-82a6-ddac58af3367.png)

Under the `Symbol Tree` on the left pane of `ghidra`, open up `Functions` and choose to view the `main` function as it is where our code starts.

![](https://user-images.githubusercontent.com/83258849/147810921-80e19f03-721b-4784-bbaf-f23e5eb00128.png)

On the right pane, we can see the decompiled code of the `main` function.

![](https://user-images.githubusercontent.com/83258849/147811084-eca3e440-004a-419f-b115-c771ff762333.png)

Looks like the flag will be printed out if our `local_18` variable is equal to `0xcafebabe`. We can also see that the `local_18` variable is defined above in the `main` function as well. This is exactly like the `Meet Greet0r` challenge. You can refer to it for more explanation on how to overwrite a local variable on the stack through buffer overflow. We will do the same things like we did in the `Meet Greet0r` challenge :)

Goal: Overflow `local_58` buffer and overwrite `local_18` variable for `0xcafebabe`.

## Debugging

### Finding runtime address of the variable we want to overwrite

We first need to find the address where the `local_18`'s value resides on the stack.

I used `gdb-pwndbg`. You can use `gdb` for the same results but `gdb-pwndbg` reveals more information and tools that are easily accessible. Run `gdb ./Descript0r`

Now run `disass main` to disassemble the `main` function. We want to find the `cmp` instruction that compares `0xcafebabe` with a register.

![](https://user-images.githubusercontent.com/83258849/147813400-2017a161-805a-4202-81e0-7138c0926a40.png)

The value `0xcafebabe` is stored in the `eax` register (eax is just 32-bit version of the rax register, in this case, they are the same), then it checks the register against `rbp-0x10`. `rbp-0x10` should be our `local_18` variable we are looking for. Let's check the address of `rbp-0x10` during runtime. Set a breakpoint at the `cmp` instruction, `break *0x401247` in my case, then run the command `run` to start the program.

The program would ask us for input. Lets give it `AAAABBBBCCCC` so that we can easily identify where our user input starts on the stack.

The program should break at the `cmp` instruction. Now let's see where the `rbp-0x10` starts on the stack. Run `x $rbp-0x10` to check the address of the `local_18` variable. The address is `0x7fffffffe2e0`(in blue in the lower left of the image):

![](https://user-images.githubusercontent.com/83258849/147813879-64c96647-7f70-416e-a4b6-bb290fbf34e8.png)

## Finding offset needed to reach the variable

Now let's view where our user input and the `local_18` variable resides on the stack. Run `x /40wx $rsp` to view the values on the stack.

![](https://user-images.githubusercontent.com/83258849/147814052-fef29652-7972-4202-b07d-5149f4a29734.png)

We see the user input starts at `0x7fffffffe2a0` as indicated by the `0x41414141`, which is our `A`s in hex. Further down, we can see the address `0x7fffffffe2e0`, which is containing the value of our `local_18` variable.

![](https://user-images.githubusercontent.com/83258849/147814464-d0fbab06-5d3d-4177-8ff4-700262939928.png)

Counting the number of bytes we need to overwrite `local_18`, `64` bytes is needed.

## Crafting Payload and Testing Exploit

We can easily create the payload in python like in the `Meet Greet0r` challenge. We will utilize `pwntools`. I created a fake flag with the file name `flag` containing `NYP{fake_flag}` locally to simulate when the exploit works.

```python
from pwn import *

offset = 64

p = process('./Descript0r')
print(p.recv())
p.sendline(b'A'*64 + p64(0xcafebabe))
print(p.recvall())
p.close()
```

![](https://user-images.githubusercontent.com/83258849/147814773-46748c6e-1836-41fa-8c14-9d93eded4674.png)

We successfully printed out the flag! Sad that I wasn't able to test this remotely :(

#### \*\*This isn't the complete solution as clarified by `Carl`, the creator of this challenge. Just changing the variable isn't enough. Running the exploit python code will return contents of the 'flag' file, but it does not contain the flag. As pointed out by `Carl`, we have to overwrite value of the `file descriptor` (local\_c) with the value `5` as well so that read() would read from STDIN (5-5=0, which is STDIN).\*\*
