# Lost my "homework" again!

## Description

> Oh no! A virus just stole my master key to my homework folder and encrypted it! It looks like it ran 2 different functions on my master key and gave me back a whole mess of numbers in txt.txt.

> Thankfully, I managed to find the virus programs, but I don't understand the code at all! Could you help me retrieve my master key again so I can continue doing my "homework"?

> Author: **Carl Voller**

We are also given 4 different files for the challenge.

```
README.md
txt.txt
virus1.s
virus2.
```

**NOTE: This write up is to explain the basics of assembly in detail. If you don't know what registers are, you can just think of it as a storage space to store a value for this moment.**

## Content

**This write up is VERY long as it goes in-depth on analysis of the assembly instructions, I deeply apologize.**

This are the main contents in this write up :)

* [Analyse and decode virus2.s](./#analysing-virus2s)
* [Analyse and decode virus1.s](./#analysing-virus1s)
* [Reversing](./#reversing)

### The Challenge

Reading README.md, one sentence to note in the file is:

`"For every character X, X was passed into virus1.s which produces the first line of output in txt.txt X was passed into virus2.s which produces the second line of output in txt.txt"`

This means that a file containing the text that we want to recover is fed and ran in both **virus1.s** and **virus2.s**, producing the two lines in **txt.txt**.

**virus1.s** produces:

`48 66 66 48 63 81 39 78 57 36 42 75 54 57 75 66 54 51 48 81 45 27 24 66 63 39 66 66 45 51 48 66 66 81 39 66 54 81 36 81 48 39 21 33`

**virus2.s** produces:

`0 0 0 1 1 2 2 1 2 0 2 1 1 3 0 2 1 0 2 2 1 2 1 1 2 0 0 2 1 0 2 2 3 2 2 2 1 2 1 3 0 0 0 1`

We can determine the length of the text that needs to be recovered is `44` characters by referring to the output of the 'virus programs'.

Now we have to analyze what the code in the 'virus programs' are actually doing.

## Analysing virus2.s

We will first analyze **virus2.s** as it is simpler to reverse.

#### virus2.s

```
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

### Decoding virus2.s

The first line is

```
mov X0, #122             ; This number is substituted with the input
```

Whatever comes after `;` is a comment, and the instruction is as the comment states: `#122` is supposed to represent the decimal number `122` but it is replaced with the user input in this case.

`mov` is the instruction, `X0` is a register, and `#122` is also a register containing a decimal representation of each character in the text.

> The mov instruction copies the data item referred to by its second operand (i.e. register contents, memory contents, or a constant value) into the location referred to by its first operand. > [source](https://www.cs.virginia.edu/\~evans/cs216/guides/x86.html)

So in this case, it is copying the data from a register that contains our chars in decimal, into the X0 register. If the instruction is `mov X0, X1`, it would copy data from X1 register into the X0 register.

###

#### Examining instructions under factor 1

```
    ; factor 1
	mov X19, #20
    sub X0, X0, X19
```

The first line `mov X19, #20` means that it would copy the number `20` into the `X19` register. So the `X19` register would contain the value `20` in it. Pretty simple.

The next line is `sub X0, X0, X19`. This line uses the `sub` instruction, which is to `subtract` values in two registers.

The format that this `sub` instruction takes is `sub {Rd}, Rn, Operand2`, where

> **Rd** is the destination register to store the result of the subtraction.

> **Rn** is the register holding the first number to subtract from.

> **Operand2** is the register holding the number to subtract from the number in the **Rn** register.

([Source](https://www.keil.com/support/man/docs/armasm/armasm\_dom1361289908389.htm))

So in this case, `sub X0, X0, X19` subtracts the value in the `X19` register from the value in `X0` register and stores the results into the `X0` register. Basically `X0=X0-X19`.

Since `X19` contains `20` and `X0` would contain each character in the text, we can represent these parts in a short python code:

```python
for char in text:
	char = ord(char) - 20
```

Where `char` would represent the `X0` register and `20` representing the `X19` register. `ord()` is just to convert the ascii characters into decimal.

###

#### Examining instructions under factor 2

```
    ; factor 2
    mov X19, #4
    udiv X20, X0, X19
    msub X21, X20, X19, X0
    
    mov X0, X21
```

The first line `mov X19, #4` would copy the number `4` into the `X19` register. So now `X19` contains the value `4`.

The second line `udiv X20, X0, X19` is using a `udiv` instruction which is short for `unsigned divide`. If you are unfamiliar with `signed` vs `unsigned`, `signed` just means that the result can go into the negatives, meaning < 0, while `unsigned` means that the results can only be positive, >= 0.

Similar to `sub` instruction, the format for `udiv` is `udiv{cond} {Rd}, Rn, Rm`, where

> **Rd** is the destination register to store the result of the division.

> **Rn** is the register holding the value to be divided.

> **Rm** is the register holding the divisor.

**Note that udiv only stores the result as an integer, not float! So the result that udiv stores of 41 / 10 is 4, not 4.1.**

So `udiv X20, X0, X19` would mean to divide the value in `X0` with the divisor in `X19` and storing the result in the `X20` register. Basically `X20=X0//X19`.

`X0` stores the value of each character - `20`, and `X19` stores the value `4`.

Then the third line `msub X21, X20, X19, X0` is using the `msub` instruction which is short for `multiplicative subtract`

The format for `msub` is `msub Xd, Xn, Xm, Xa`, where

> **Xd** is the destination register to store the result of the instruction.

> **Xn** is the register that store the multiplicand.

> **Xm** is the register that stores the multiplier.

> **Xa** is the register that stores the number to be subtracted from.

So `msub X21, X20, X19, X0` means to `multiply` the value in `X20` register with the value in `X19` register, `subtract` that value from the value in `X0`, then store the result into the `X21` register. Basically `X21=X0-(X20*X19)`.

The last line `mov X0, X21` just moves the end result into the `X0` register. The value in the `X0` register would be the end result to be returned from the program.

The last few instructions under `;syscall to exit` is to just exit the program.

### Simplifying virus2.s

After decoding what the program does, we can replicate what the program does in python. But first, let's see an example of the flow if a value is fed into the program.

#### virus2.s

```
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

#### Example (Feeding 81 into the program)

```
.global _start
.align 2

_start:

    mov X0, #122    		; X0 = 81

    ; factor 1
	mov X19, #20		; X19 = 20
    sub X0, X0, X19		; X0 = X0 - X19, so X0 = 81 - 20, X0 = 61
    
    ; factor 2
    mov X19, #4			; X19 = 4
    udiv X20, X0, X19		; X20 = X0 // X19, so X20 = 61 // 4, X20 = 15
    msub X21, X20, X19, X0	; X21 = X0 - (X20 * X19), so X21 = 61 - (15 * 4), X21 = 1
    
    mov X0, X21			; X0 = X21, so X0 = 1, 1 is returned

    ;; syscall to exit
	mov X16, #1
	svc #0x80
```

From the example given, it is clear that all the program does is to return the modulus of each character in the text after subtracting 20 from them. So we craft a simpler python script that does the same...

#### virus2.py (simplify)

```python
def virus2(text):
	result = []
	for char in text:
		temp = ord(char) - 20
		result.append(str(temp % 4))
	return ' '.join(result)
```

\
\


## Analysing virus1.s

#### virus1.s

```
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
    add X0, X21, X20		; This line and the instructions under factor 3 are new
	
    ; factor 3
    mov X19, #3
    mul X0, X0, X19

    ;; syscall to exit
	mov X16, #1
	svc #0x80
```

As we can see, the first few lines of instructions are exactly the same as those in virus2.s. There are only 3 new instructions in this program as marked in the code preview above.

So the program does the same function as virus2.s: the subtracting 20 from the character and adding it to `X0` register, then modulus that value by `4` and storing the result in the `X21` register.

### Decoding virus1.s

We will decode the 3 new instructions.

```
    add X0, X21, X20		; This line and the instructions under factor 3 are new
	
    ; factor 3
    mov X19, #3
    mul X0, X0, X19
```

The first new instruction after the `msub` instruction is `add X0, X21, X20`, and as you guess it, it **adds** the values in the `X21` register and the value in `X20` register together and stores the result in the `X0` register. Basically `X0=X21+X20`.

In this case, `X0` contains the (character - 20)//4, and `X21` contains our modulus result (remainder after dividing by 4).

###

#### Examining instructions under factor 3

```
    ; factor 3
    mov X19, #3
    mul X0, X0, X19
```

The first line `mov X19, #3` is just to move the value `3` into the `X19` register.

The second line `mul X0, X0, X19` uses the instruction `mul`, which is just **multiplying** the value in the `X0` register with the value in the `X19` register and storing it into the `X0` register. Basically `X0=X0*X19`. This result in the `X0` will then be returned as it is the end of the program after this instruction.

### Simplifying virus1.s

#### virus1.s

```
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
    add X0, X21, X20

    ; factor 3
    mov X19, #3
    mul X0, X0, X19

    ;; syscall to exit
	mov X16, #1
	svc #0x80
```

#### Example (Feeding 81 into the program, same example used in virus2.s above)

```
.global _start
.align 2

_start:

    mov X0, #122		; X0 = 81
    ; factor 1
	mov X19, #20		; X19 = 20
    sub X0, X0, X19		; X0 = X0 - X19, so X0 = 81 - 20, X0 = 61
    
    ; factor 2
    mov X19, #4			; X19 = 4
    udiv X20, X0, X19		; X20 = X0 // X19, so X20 = 61 // 4, X20 = 15
    msub X21, X20, X19, X0	; X21 = X0 - (X20 * X19), so X21 = 61 - (15 * 4), X21 = 1
    add X0, X21, X20		; X0 = X21 + X20, so X0 = 1 + 15, X0 = 16

    ; factor 3
    mov X19, #3			; X19 = 3
    mul X0, X0, X19		; X0 = X0 * X19, so X0 = 16 * 3, X0 = 48, 48 is returned

    ;; syscall to exit
	mov X16, #1
	svc #0x80
```

From this, we can see that if 81 is fed into the two programs, it will output

> `48` for virus1.s

> `1` for virus2.s

#### virus1.py (simplify)

```python
def virus1(text):
	result = []
	for char in text:
		temp = ord(char) - 20
		remainder = temp % 4
		quotient = temp // 4
		result.append(str((quotient + remainder) * 3))
	return ' '.join(result)
```

\


## Reversing

So now we know what `virus1.s` and `virus2.s` do, and we know the output of the two programs after the text we wanna find is fed into them, we can easily create a decode script and use the two lines of output to find the original text.

#### virus1.py

```python
def virus1(text):
	result = []
	for char in text:
		temp = ord(char) - 20
		remainder = temp % 4
		quotient = temp // 4
		result.append(str((quotient + remainder) * 3))
	return ' '.join(result)
```

#### virus2.py

```python
def virus2(text):
	result = []
	for char in text:
		temp = ord(char) - 20
		result.append(str(temp % 4))
	return ' '.join(result)
```

#### txt.txt

```
48 66 66 48 63 81 39 78 57 36 42 75 54 57 75 66 54 51 48 81 45 27 24 66 63 39 66 66 45 51 48 66 66 81 39 66 54 81 36 81 48 39 21 33
0 0 0 1 1 2 2 1 2 0 2 1 1 3 0 2 1 0 2 2 1 2 1 1 2 0 0 2 1 0 2 2 3 2 2 2 1 2 1 3 0 0 0 1
```

#### solve.py

```python
v1 = "48 66 66 48 63 81 39 78 57 36 42 75 54 57 75 66 54 51 48 81 45 27 24 66 63 39 66 66 45 51 48 66 66 81 39 66 54 81 36 81 48 39 21 33"
v2 = "0 0 0 1 1 2 2 1 2 0 2 1 1 3 0 2 1 0 2 2 1 2 1 1 2 0 0 2 1 0 2 2 3 2 2 2 1 2 1 3 0 0 0 1"

v1 = v1.split(' ')
v2 = v2.split(' ')

flag = []

for i in range(len(v1)):
	res = int(v1[i])/3
	m = res - int(v2[i])
	char = (m*4) + int(v2[i]) + 20
	flag.append(chr(int(char)))

print(''.join(flag))
```

The output will be `TllQezByZDFuYWxfYXNzM21ibHlfMXNfczBfYzAwTH0=`. Base64 decode it and you get the flag.

`flag = NYP{0rd1nal_ass3mbly_1s_s0_c00L}`

I placed the python scripts I created under the `tools` directory.
