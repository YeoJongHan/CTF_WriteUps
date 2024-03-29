# Wait For The Day

## Description

> Momma bought a Christmas gift for you. She says it's something you love! But Christmas is like more than 6 months away :/ Try to peek in and find out what the gift is, before the Christmas eve ;)

{% file src="../../../challenge_files/STANDCON_2022/Reverse/Wait For The Day/challenge/gift_for_you" %}

### TL;DR

* Patch binary to bypass checks
* Run binary through gdb to get flag in memory
* Get flag

## Solution

### Analysis

We are given a file with no extension. Running `file gift_for_you` returns that it is a binary file, so change permissions to allow it to be executable.

<figure><img src="https://user-images.githubusercontent.com/83258849/174606846-382fac86-9c97-4a6f-bc9f-a4a7768abff9.png" alt=""><figcaption><p><mark style="color:red;"><strong>file gift_for_you</strong></mark></p></figcaption></figure>

For such challenges, I would usually run the binary first to see what it does (don't run untrusted software >\_>).

We see the following result without the need to supply any user input.

<figure><img src="https://user-images.githubusercontent.com/83258849/174608715-dbac0e71-6e92-4a8a-bc03-6c07589cce50.png" alt=""><figcaption><p><mark style="color:red;"><strong>./gift_for_you</strong></mark></p></figcaption></figure>

Firing up `ghidra`, we can analyze the `main` function of the binary.

![](https://user-images.githubusercontent.com/83258849/174609347-5ff52bc2-3691-494e-a31a-993f88c16edd.png)

The binary performs some check against the current time of the local system. It checks using a custom function `time_check` and if the function returns a `0` and this `DISPATCH_GIFT` variable is equal to 0xff, then this `dispatch_gift` function will be called with the format as the flag as parameters.

<figure><img src="https://user-images.githubusercontent.com/83258849/174610399-e996a51b-7efe-4793-96a7-18bb5993c585.png" alt=""><figcaption></figcaption></figure>

So we know that `dispatch_gift` is the function that returns the flag. Let's check the decompiled code of that function.

<figure><img src="https://user-images.githubusercontent.com/83258849/174610883-441e18ee-1c8a-4a06-8e73-73dec41f2105.png" alt=""><figcaption></figcaption></figure>

This is too much code for me to spend my limited time to try to understand, but one of the line that caught my attention is `"Gift has been stored safely in memory"`.

Since the "Gift" or flag is stored in memory when the binary is running, and the `dispatch_gift` function is not affected by the `time_check` function, we can thus patch the binary to jump straight past the `time_check` function and straight to `dispatch_gift`. Then we can find the flag in memory through `gdb`.

### Patching The Binary

I used [Radare 2](https://rada.re/n/radare2.html) to patch the binary.

1. Run `r2 -A -w gift_for_you` to 'write' on the binary.
2. Run `aaaa` to run all analysis on the binary (usually not necessary).
3. Step into the main function with `s main`.

![](https://user-images.githubusercontent.com/83258849/174615940-dc2a9b73-82dc-4849-901c-c231dda054cc.png)

1. Run `pdf` to view the `main` function in assembly.
2. Find the first jump instruction (jmp,je,jne etc.) and note the address of it. This is the first `if` statement we see in `ghidra` and we want to patch it to jump straight to the address where it gets ready to call `dispatch_gift`.
3. Then find the address where it gets ready to call `dispatch_gift`.

![Looking for address](https://user-images.githubusercontent.com/83258849/174617958-70d27184-245b-4707-b273-e5bb273a2b1c.png)

1. Step into the jump address we got by running the command `s 0x12f2`.
2. Patch instruction to jump to dispatch\_gift by running `wa jmp 0x1301`, then quit with `q`.

![](https://user-images.githubusercontent.com/83258849/174618713-d98f21da-ef30-4b8c-80a9-e4a56df7460e.png)

Now running the binary again, we can see that the output is different, means we successfully patched it!

![](https://user-images.githubusercontent.com/83258849/174618882-c3196ac7-fd7b-4279-9ecc-5048259ab72a.png)

### Getting flag from memory

1. Run the binary through gdb: `gdb gift_for_you`
2. Set a breakpoint at dispatch\_gift: `break dispatch_gift`
3. Run the binary: `run`
4. Program should break at breakpoint
5. Disassemble dispatch\_gift to find return address to break at: `disass dispatch_gift`, then `break *<ret addr>`

![](https://user-images.githubusercontent.com/83258849/174620636-c14d555b-d7b1-4d43-8f8d-373de3aa5f87.png)

1. Continue the execution: `c`
2. Program should break at ret (breakpoint 2)
3. There should be an address returned by the binary on where the flag is at. Print the value at the address in string format by running `x/s <addr>`, or if you are using `gdb-pwndbg`, you can just run `search "STANDCON"`.

![](https://user-images.githubusercontent.com/83258849/174621594-298e6c46-93ee-47fc-8be4-217143c97716.png)

![Flag found](https://user-images.githubusercontent.com/83258849/174621658-42b7cb1f-fb0c-43b7-83f8-5287b075b5f1.png)
