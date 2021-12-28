# Description
>Oh no! A virus just stole my master key to my homework folder and encrypted it! It looks like it ran 2 different functions on my master key and gave me back a whole mess of numbers in txt.txt.

>Thankfully, I managed to find the virus programs, but I don't understand the code at all! Could you help me retrieve my master key again so I can continue doing my "homework"?

We are also given 4 different files for the challenge.
```
README.md
txt.txt
virus1.s
virus2.
```

**NOTE: This write up is to explain the basics of assembly in detail. If you don't know what registers are, you can just think of it as a storage space to store a value for this moment.**
## The Challenge
Reading README.md, one sentence to note in the file is:

`"For every character X, X was passed into virus1.s which produces the first line of output in txt.txt X was passed into virus2.s which produces the second line of output in txt.txt"`

This means that a file containing the text that we want to recover is fed and ran in both **virus1.s** and **virus2.s**, producing the two lines in **txt.txt**.

**virus1.s** produces:

`48 66 66 48 63 81 39 78 57 36 42 75 54 57 75 66 54 51 48 81 45 27 24 66 63 39 66 66 45 51 48 66 66 81 39 66 54 81 36 81 48 39 21 33`

**virus2.s** produces:

`0 0 0 1 1 2 2 1 2 0 2 1 1 3 0 2 1 0 2 2 1 2 1 1 2 0 0 2 1 0 2 2 3 2 2 2 1 2 1 3 0 0 0 1`

We can determine the length of the text that needs to be recovered is `44` characters by referring to the output of the 'virus programs'.

Now we have to analyze what the code in the 'virus programs' are actually doing.
## Analysis
We will first analyze **virus2.s** as it is simpler to reverse.

### virus2.s
```assembly
.global _start
.align 2

_start:

    mov X0, #122             ; This number is substituted with the input

    ; factor 1
	mov X19, #20
    sub X0, X0, X19
    
    ; factor 2
    mov X19, #4
    udiv X20, X0, X19
    msub X21, X20, X19, X0
    
    mov X0, X21

    ;; syscall to exit
	mov X16, #1
	svc #0x80
```
We can see that this is written in `assembly language` based on the `.s` file extension and the instructions such as `mov` and `sub` in the file.

The first two lines "`.global _start`" and "`.align 2`" is to tell the system where to start the instructions and how the instructions should be executed, it can be ignored in this challenge but you can read up more on them from [here](https://stackoverflow.com/questions/17898989/what-is-global-start-in-assembly-language) and [here](https://stackoverflow.com/questions/11277652/what-is-the-meaning-of-align-an-the-start-of-a-section).

`_start:` indicates the start of the instructions, just like main() in C.
## 
The first line is
```assembly
mov X0, #122             ; This number is substituted with the input
```
Whatever comes after `;` is a comment, and the instruction is as the comment states: `#122` is supposed to represent the decimal number `122` but it is replaced with the user input in this case.

`mov` is the instruction, `X0` is a register, and `#122` is also a register containing a decimal representation of each character in the text.

> The mov instruction copies the data item referred to by its second operand (i.e. register contents, memory contents, or a constant value) into the location referred to by its first operand. > [source](https://www.cs.virginia.edu/~evans/cs216/guides/x86.html#:~:text=The%20mov%20instruction%20copies%20the,to%2Dmemory%20moves%20are%20not.)

So in this case, it is copying the data from a register that contains our chars in decimal, into the X0 register. If the instruction is `mov X0, X1`, it would copy data from X1 register into the X0 register.
## 
### Examining instructions under factor 1
```assembly
    ; factor 1
	mov X19, #20
    sub X0, X0, X19
```
The first line `mov X19, #20` means that it would copy the number `20` into the `X19` register. So the `X19` register would contain the value `20` in it. Pretty simple.

The next line is `sub X0, X0, X19`. This line uses the `sub` instruction, which is to `subtract` values in two registers.

The format that this `sub` instruction takes is `sub {Rd}, Rn, Operand2`, where 
> **Rd** is the destination register to store the result of the subtraction

> **Rn** is the register holding the first number to subtract from

> **Operand2** is the register holding the number to subtract from the number in the **Rn** register.

([Source](https://www.keil.com/support/man/docs/armasm/armasm_dom1361289908389.htm))

So in this case, `sub X0, X0, X19` subtracts the value in the `X19` register from the value in `X0` register and stores the results into the `X0` register. Basically `X0=X0-X19`.

Since `X19` contains `20` and `X0` would contain each character in the text, we can represent these parts in a short python code:
```python
for char in text:
	char = ord(char) - 20
```
