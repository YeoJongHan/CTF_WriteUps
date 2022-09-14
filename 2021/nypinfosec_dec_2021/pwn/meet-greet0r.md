# Meet Greet0r

## Description

> Meet Greet0r! He's a cute little program that is absolutely just DYING to meet new people.

> Talk to Greet0r 🤖:

> `nc meet-greet0r.nypinfsecctf.tk 8003`

> Author: **Carl Voller**

The source code for the program was given `Greet0r.c`

## The Challenge

```
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h> 
#include <unistd.h>

int main() {

    char name [52];
    int loopCount = 4;

    printf("Hello! I'm so excited to meet you! What's your name?\n");

    gets(name);

    for (int i = 0; i < loopCount; i++) {
        printf("Hello %s!! Hope you're having a fantastic day!\n", name);
        if (i == 5) {
            char *flag = malloc(0x100);
            int fd = open("flag", 0);
            read(fd, flag, 0x100);
            printf("I've never been so excited to meet someone before! Here, take this flag, you deserve it :)\n%s\n", flag);
            close(fd);
        }
    }

    return 0;
}
```

This program is written in `C`. We should try running the `netcat` command first and see what it does.

The program just asks for our name and it greets us by printing `Hello <name>!! Hope you're having a fantastic day!` 4 times.

## Examining the code

Checking the source code, we can see a portion of the code where it opens the flag and prints it out. This is only if the variable `i` is equal to `5`.

We can also see a clear `Buffer Overflow` vulnerability for the variable `name`.

The first line of code assigns a buffer of `52` bytes (characters) for the variable `name`:

```
char name [52];
```

Below, we can see that the program uses the `gets()` function to retrieve data from the user and puts it into the variable `name`.

```
gets(name);
```

`gets()` is a vulnerable function as it does not have any checks on how many characters it will read.

As indicated by `man gets`'s Linux Programmer's Manual,

> Never use gets(). Because it is impossible to tell without knowing the data in advance how many characters gets() will read, and because gets() will continue to store characters past the end of the buffer, it is extremely dangerous to use. It has been used to break computer security. Use fgets() instead.

Since the `name` variable can only store `52` bytes of data, if we send a string more than `52` bytes, we can overflow the buffer and overwrite the values on the stack.

Our goal is to make `i == 5` at one point. However, the normal code never allows `i` to be more than `3` based on the `for` loop used, where `loopCount` is defined as `4` in the first few lines.

```
for (int i = 0; i < loopCount; i++){
  ...
}
```

Since `loopCount` is defined in the same function as the `name` variable, it means that the value is on the "same stack" and we can overwrite it.

## Buffer Overflow

**Note: This is an explanation of simple buffer overflow exploits for beginners.**

This is a rough sketch of how the stack would look like in this example:

![stack2](https://user-images.githubusercontent.com/83258849/147780268-fe5e702d-9822-4676-8214-5f88bf055f64.png)

Using the `Buffer Overflow` exploit, our input will be moved into the `name` variable, then our remaining overflowing characters will overwrite other parts of the stack as the `name` variable can only hold `52` bytes. If we do it correctly, the remaining overflowing characters will overwrite the value in the `loopCount` variable, so we can change the value in `loopCount` to anything we want.

Illustration of Buffer Overflow:

![bof](https://user-images.githubusercontent.com/83258849/147780233-a1a446e9-3f43-493d-86ee-e29b86b1fa5c.png)

## Getting Started

I compiled the C source code given and ran the program locally to understand more in-depth on how we can go about changing the value of `loopCount`.

Run `gcc Greet0r.c -o Greet0r` to compile the code into a binary.

I used `gdb-pwndbg` to debug the program during runtime. You can install it from their main github page [https://github.com/pwndbg/pwndbg](https://github.com/pwndbg/pwndbg). Run `gdb ./Greet0r` and run `disass main` to disassemble the `main` function.

![image](https://user-images.githubusercontent.com/83258849/147777561-793ec896-0aad-4517-bbb7-8493ce4d1911.png)

It is a lot to take in and may be overwhelming, but it is pretty simple once you understand how the instructions are ran.

At the first few lines of instructions, there is a `mov DWORD PTR [rbp-0x8], 0x4` instruction. This instruction places the number `4` into the address at `rbp-0x8`. In this case, you can view `rbp` as one of the many registers that holds a value for now. So the address at `rbp` - 8 would contain the value `4`.

![image](https://user-images.githubusercontent.com/83258849/147777761-5245e472-e585-45f5-8066-53ded66ef642.png)

This instruction is assigning the variable `loopCounter` with the value `4` as we seen in the source code!

```
int loopCount = 4;
```

At the very end of `main` function, there is a `cmp` instruction, which is for compare, and a `jl` instruction, which is a "jump if less than" instruction.

![image](https://user-images.githubusercontent.com/83258849/147777692-a3396998-e20c-444e-a035-bf5b379a16fb.png)

These instructions basically compares the value in the `eax` register, with the value at the address `rbp-0x8`. Remember that `rbp-0x8` is our `loopCount` variable containing the number `4`? These instructions makes up the `if` statement in the `for` loop, where `if i < loopCount, continue looping`

```
for (int i = 0; i < loopCount; i++){
  ...
}
```

So now we know that the value of `loopCount` is stored in the address at `rbp-0x8`. Let's see where that is on our stack.

## Finding where loopCount resides on the Stack

Running `gdb-pwndbg` on the program, we can set a breakpoint at `main` by running `break main`, then we grab the address of the compare instruction, which is `0x1251` in my case. (the address may be different for you)

![image](https://user-images.githubusercontent.com/83258849/147777692-a3396998-e20c-444e-a035-bf5b379a16fb.png)

Run the program in `gdb-pwndbg` by running the command `run`, the program should stop at a breakpoint at main. Now set a breakpoint at the address of the compare function during runtime by running the command `breakrva <address>`, in my case would be `breakrva 0x1251`. This should set a second breakpoint. Continue the program by running `c`. The program will ask for the user input like the normal program.

![image](https://user-images.githubusercontent.com/83258849/147778930-4eec17f5-70e1-4d45-a8db-6131f70ba0b4.png)

Enter `john` or any string you want. The program should hit another breakpoint at the compare function. The string you entered into the program should be seen in the `RSP` register, the `stack pointer`, which is where your stack resides.

![image](https://user-images.githubusercontent.com/83258849/147779018-71e74c08-c923-4d1c-9360-7778e6c28cd4.png)

We can examine the value in the `loopCount` variable by examining the address at `rbp-0x8`. Run the command `x $rbp-0x8` to examine the value at the address. It should show that it contains a value `4` as long as the user input is not too long.

![image](https://user-images.githubusercontent.com/83258849/147779219-4d1c8aa3-b3f4-41cd-a09f-208844eaa4a1.png)

Note the actual address of `rbp-0x8` during runtime (hex address at left side). In my case, it is `0x7fffffffe2f8`.

Now let's examine the values on the stack by running the command `x /40wx $rsp`. The first few hex values would contain the string that you have input into the program, in `little endian` format and in hex.

![image](https://user-images.githubusercontent.com/83258849/147779490-9f2ad751-2ecb-4417-9588-7529aac0d5bf.png)

Notice how the address of `loopCount` is in the stack? You can see from my example that the value `0x4` is at the address `0x7fffffffe2f8`, which is residing on the stack.

![stack](https://user-images.githubusercontent.com/83258849/147779765-c1965924-7753-42f5-a938-9a601564d3f0.png)

We can then count that we need `72` characters until we reach our `loopCount` value (1 character is 2 hex digits).

Let's try to test if this is correct. Print `72` characters, then overwrite it something we can identify. We can use "`BBBB`" as it is easily identifiable in hex as `0x42424242`. We can just use python for creating the test payload, run `python3 -c "print('A'*72 \+ 'B'*4)"`.

Run a new instance of `gdb-pwndbg` on the program, set break at main, copy the address at the `cmp` instruction, run the program, then break at the `cmp` instruction address copied (what we did above. Enter `c` to continue, then enter the payload when the program asks for user input.

Now check the value stored in `loopCount`, which is at `rbp-0x8`. Run the command `x $rbp-0x8`. The value at that address is overwritten with `0x42424242`, which is our `B`s!

![image](https://user-images.githubusercontent.com/83258849/147780995-ab42b828-123e-4490-a848-f68f1601117e.png)

Technically the flag is already printed, but it's hard to tell as there are many statements being printed. Let's try to overwrite the value in `loopCount` to only `6` so that our flag is printed.

Change the payload from `'A'*72\+'B'*4` to `'A'*72+'\x06\x00\x00\x00'`. This sets the value to only `6` as `0x06` is `6` in decimal, and the `\x06` is the first byte as the program would read the input in `little endian` format. Since we can't print and copy '`\x06\x00\x00\x00`', we need to send the raw output to a file. We can do this through python.

```python
f.open('payload.txt', 'wb')
f.write(b'A'*72+b'\x06\x00\x00\x00')
f.close()
```

We can use python's `pwntools` as well:

```python
from pwn import *

p = process('./Greet0r')

print(p.recv())
p.sendline(b'A'*72+b'\x06\x00\x00\x00')
print(p.recvall())
p.close()
```

![image](https://user-images.githubusercontent.com/83258849/147781730-69970f78-e359-467e-a905-3dc8487f64bc.png)

Change `p = process('./Greet0r')` to access the target host `p = remote('<host>', <port>)` and we should get our flag!

_I didn't keep note of the actual flag, sorry :(_

Here is a good youtube video on how it works, created by our beloved **LiveOverFlow**: [https://www.youtube.com/watch?v=T03idxny9jE](https://www.youtube.com/watch?v=T03idxny9jE)
