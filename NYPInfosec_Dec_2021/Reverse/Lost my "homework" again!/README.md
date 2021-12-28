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
