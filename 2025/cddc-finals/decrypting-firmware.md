# Decrypting Firmware

## Description

> Bootloader Base Address : 0x21000000
>
>
>
> Kernel Base Address : 0xc0008000

{% file src="../../.gitbook/assets/chal.tar" %}

## Solution

Only looked at this when the CTF ended :croissant:

### TL;DR

* Search for article on reversing u-boot IoT firmware
* Copy paste emulator code, modify it accordingly, then run to decrypt the kernel image
* Use `vmlinux-to-elf` to convert kernel to an elf file to reverse it
* Discover `block_aes_decrypt` and other key initializing functions, run similar emulator to emulate the functions to:
  * Get the aes key
  * Decrypt romfs using the aes key

## Analysis

### Starting Off

We are given 3 files:

1. `dhboot.bin.img` - U-boot bootloader
2. `kernel.img` -  Encrypted kernel image
3. `romfs-x.squashfs.img` - Encrypt SquashFS root filesystem image

Starting off without any knowledge on the boot up sequence of any firmware, we can guess that `dhboot.bin.img` would start executing first during boot up.

With the help of a friend, I was told to search up "reversing uboot iot firmware" and refer to this site to decrypt the firmware:

* [https://www.shielder.com/blog/2022/03/reversing-embedded-device-bootloader-u-boot-p.1/](https://www.shielder.com/blog/2022/03/reversing-embedded-device-bootloader-u-boot-p.1/)

The article states to use `binwalk --entropy <file>` as to check whether the file has been encrypted or not. This is a check on how "random" the bytes are (less entropy mean several 0s in some areas or certain repeated patterns, for e.g.), encrypted files would have a high entropy due to their "randomness".

<figure><img src="../../.gitbook/assets/entropy.png" alt=""><figcaption><p>File entropies</p></figcaption></figure>

As seen above, both the `kernel` and `romfs` seems to have consistently **high entropies** throughout the file, highly indicating that they're encrypted. This is similar to what is shown in the article, where it indicates that `dhboot` is likely to not be encrypted.

The rest of the details can be read up on the article itself, where they nicely explain on how they reversed the u-boot, to how they managed to decrypt the kernel.

However, I will properly provide some details on how to load the u-boot into ghidra for static analysis as this can be useful for future challenges (custom u-boot perhaps?).

### Decompiling U-Boot

Opening the file in Ghidra, we first select the `Language` to be `ARMv7 Little Endian` (following the article).

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption><p>Selecting Language</p></figcaption></figure>

Click OK to select the language, then click on the `Options...` button at the bottom right of the window, setting the `Block Name` to anything, the `Base Address` as `0x21000000` as per the challenge description, then the `File Offset` would be where the code starts.

To determine where the code starts, we can do a rough guess on where the entropy starts in the file, by running `hexdump -C ./dhboot.bin.img | head -n 50` and checking where the bunch of `00`s stop. (thank Jin Kai for this trick)

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

In the image above, we can guess that the code starts at the `0x840` offset of the file, so we set this in the `File Offset` and try to decompile it.

You will receive a message on setting the `Length` to some other value, so just set it according to the message.

<figure><img src="../../.gitbook/assets/image (4).png" alt=""><figcaption><p>Options</p></figcaption></figure>

Afterwhich, the binary should be decompiled properly!

<figure><img src="../../.gitbook/assets/image (5).png" alt=""><figcaption><p>Ghidra</p></figcaption></figure>

### Firmware Decryption

Thankfully, there isn't a need for decompiling and reading code of the u-boot binary.

At the end of the article, a script is given to emulate the decryption function `block_aes_decrypt` of the bootloader:

{% tabs %}
{% tab title="original_emulator.py" %}
```python
from __future__ import print_function
from ctypes import sizeof
from unicorn import *
from unicorn.arm_const import *
from unicorn.unicorn_const import *
from capstone import *
import struct, binascii

#callback of the code hook
def hook_code(uc, addr, size, user_data): 
	mem = uc.mem_read(addr, size)
	disas_single(bytes(mem),addr)

#disassembly each istruction and print the mnemonic name
def disas_single(data,addr):
		for i in capmd.disasm(data,addr):
			print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
			break
			
#create a new instance of capstone
capmd = Cs(UC_ARCH_ARM, UC_MODE_ARM) 

#code to be emulated
in_file = open("u-boot.bin", "rb") # opening for [r]eading as [b]inary
ARM_CODE32 = in_file.read()
in_file.close()

# file to be decrypted
in_file = open("kernel.img.raw", "rb") # opening for [r]eading as [b]inary
FILE_TOBE_DEC = in_file.read()
in_file.close()

# U-Boot base address
# we have seen this in the previous article (DDR start at 8000_0000)
ADDRESS = 0x80800000

print("Emulate ARM code")
print("Shielder")
try:
    # Initialize emulator in ARM-32bit mode
    # with "ARM" ARM instruction set
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

    # map U-boot in memory for this emulation
    # "// (1024 * 1024)" for memory allign pourses
    i = len(ARM_CODE32) // (1024 * 1024)
    mem_size = (1024 * 1024) + (i * (1024 * 1024))
    mu.mem_map(ADDRESS, mem_size, perms=UC_PROT_ALL)
    # write machine code to be emulated to memory
    mu.mem_write(ADDRESS, ARM_CODE32)
    
    # map STACK
    stack_address = ADDRESS + mem_size
    # 2MB 
    stack_size = (1024 * 1024) * 2
    mu.mem_map(stack_address, stack_size, perms=UC_PROT_ALL)
    
    # map the Kernel in RAM memory for this emulation
    # remember that RAM starts at 8000_0000
    # there we call RAM a sub-region of memory inside the RAM itself 
    ram_address = ADDRESS + mem_size + stack_size
    ram_size = (1024 * 1024) * 8
    mu.mem_map(ram_address, ram_size, perms=UC_PROT_ALL)
    # write file to be decrypted to memory
    mu.mem_write(ram_address, FILE_TOBE_DEC)

    # initialize machine registries
    mu.reg_write(UC_ARM_REG_SP, stack_address)
    # first argument, memory pointer to the location of the file
    mu.reg_write(UC_ARM_REG_R0, ram_address)
    # second argument, memory pointer to the location on which write the file
    mu.reg_write(UC_ARM_REG_R1, ram_address) 
    # third argument, block size to be read from memory pointed by r0
    mu.reg_write(UC_ARM_REG_R2, 512) 

    # hook any instruction and disassembly them with capstone
    mu.hook_add(UC_HOOK_CODE, hook_code)

    # emulate code in infinite time
    # Address + start/end of the block_aes_decrypt function
    # this trick save much headaches
    mu.emu_start(ADDRESS+0x8c40, ADDRESS+0x8c44) 

    # now print out some registers
    print("Emulation done. Below is the CPU context")

    r_r0 = mu.reg_read(UC_ARM_REG_R0)
    r_r1 = mu.reg_read(UC_ARM_REG_R1)
    r_r2 = mu.reg_read(UC_ARM_REG_R2)
    r_pc = mu.reg_read(UC_ARM_REG_PC)
    print(">>> r0 = 0x%x" %r_r0)
    print(">>> r1 = 0x%x" %r_r1)
    print(">>> r2 = 0x%x" %r_r2)
    print(">>> pc = 0x%x" %r_pc)

    print("\nReading data from first 512byte of the RAM at: "+hex(ram_address))
    print("==== BEGIN ====")
    ram_data = mu.mem_read(ram_address, 512)
    print(str(binascii.hexlify(ram_data)))
    print("==== END ====")

    # from the reversed binary, we know which are the magic bytes
    # at the beginning of the kernel
    if b"27051956" == binascii.hexlify(bytearray(ram_data[:4])):
        print("\nMagic Bytes match :)\n\n")
        with open("test.bin", "wb") as f:
            f.write(ram_data)

except UcError as e:
    print("ERROR: %s" % e)
```
{% endtab %}
{% endtabs %}

To decrypt the kernel that we have, we have to modify the code to work on our kernel image.

We have to modify

* `ARM_CODE32` to contain just the u-boot code, which as we found before is at the `0x840` offset.
* `FILE_TOBE_DEC` also have to be changed to only include the encrypted part of the kernel image, so we can skip past the 64 bytes header.
* `ADDRESS` to start at `0x21000000`
* Add a `SIZE` to calculate the **size of the kernel image file - 0x40 bytes for header**. Use this `SIZE` to be placed into the `R2` register, and also to be read from `ram_address`.

Lastly, we have to modify the `start` and `end` addresses of the emulator according to the `block_aes_decrypt` function call address. We can find this address by searching for the string "decrypt" in Ghidra, and cross referencing the article's screenshot of the decompiled code.

<figure><img src="../../.gitbook/assets/image (6).png" alt=""><figcaption><p>Finding "decrypt" string</p></figcaption></figure>

Jumping to the address of this function in IDA (0x2101305c), we can see a cleaner decompiled code (as compared to Ghidra). Using the strings as context clues, we can guess what each function represents, and so we find the `block_aes_decrypt` function based on the error message.

<figure><img src="../../.gitbook/assets/image (7).png" alt=""><figcaption><p>Decompiled code in IDA</p></figcaption></figure>

We can then use the address that call this function, following the article!

<figure><img src="../../.gitbook/assets/image (8).png" alt=""><figcaption><p>Addresses for block_aes_decrypt call</p></figcaption></figure>

{% tabs %}
{% tab title="decrypt_kernel.py" %}
```python
from __future__ import print_function
from ctypes import sizeof
from unicorn import *
from unicorn.arm_const import *
from unicorn.unicorn_const import *
from capstone import *
import struct, binascii

#callback of the code hook
def hook_code(uc, addr, size, user_data): 
	mem = uc.mem_read(addr, size)
	disas_single(bytes(mem),addr)

#disassembly each istruction and print the mnemonic name
def disas_single(data,addr):
		for i in capmd.disasm(data,addr):
			print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
			break
			
#create a new instance of capstone
capmd = Cs(UC_ARCH_ARM, UC_MODE_ARM) 

#code to be emulated
in_file = open("dhboot.bin.img", "rb") # opening for [r]eading as [b]inary
ARM_CODE32 = in_file.read()[0x840:]
in_file.close()

# file to be decrypted
in_file = open("kernel.img", "rb") # opening for [r]eading as [b]inary
FILE_TOBE_DEC = in_file.read()[0x40:]
in_file.close()

# U-Boot base address
# we have seen this in the previous article (DDR start at 8000_0000)
ADDRESS = 0x21000000

KERNEL_START = 0x40
KERNEL_SIZE = 0x2792f8 # total size of kernel image file
SIZE = KERNEL_SIZE - KERNEL_START

print("Emulate ARM code")
print("Shielder")
try:
    # Initialize emulator in ARM-32bit mode
    # with "ARM" ARM instruction set
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

    # map U-boot in memory for this emulation
    # "// (1024 * 1024)" for memory allign pourses
    i = len(ARM_CODE32) // (1024 * 1024)
    mem_size = (1024 * 1024) + (i * (1024 * 1024))
    mu.mem_map(ADDRESS, mem_size, perms=UC_PROT_ALL)
    # write machine code to be emulated to memory
    mu.mem_write(ADDRESS, ARM_CODE32)
    
    # map STACK
    stack_address = ADDRESS + mem_size
    # 2MB 
    stack_size = (1024 * 1024) * 2
    mu.mem_map(stack_address, stack_size, perms=UC_PROT_ALL)
    
    # map the Kernel in RAM memory for this emulation
    # remember that RAM starts at 8000_0000
    # there we call RAM a sub-region of memory inside the RAM itself 
    ram_address = ADDRESS + mem_size + stack_size
    ram_size = (1024 * 1024) * 8
    mu.mem_map(ram_address, ram_size, perms=UC_PROT_ALL)
    # write file to be decrypted to memory
    mu.mem_write(ram_address, FILE_TOBE_DEC)

    # initialize machine registries
    mu.reg_write(UC_ARM_REG_SP, stack_address)
    # first argument, memory pointer to the location of the file
    mu.reg_write(UC_ARM_REG_R0, ram_address)
    # second argument, memory pointer to the location on which write the file
    mu.reg_write(UC_ARM_REG_R1, ram_address) 
    # third argument, block size to be read from memory pointed by r0
    mu.reg_write(UC_ARM_REG_R2, SIZE) 

    # hook any instruction and disassembly them with capstone
    # mu.hook_add(UC_HOOK_CODE, hook_code)

    # emulate code in infinite time
    # Address + start/end of the block_aes_decrypt function
    # this trick save much headaches
    mu.emu_start(0x210130CC, 0x210130D0) 

    # now print out some registers
    print("Emulation done. Below is the CPU context")

    r_r0 = mu.reg_read(UC_ARM_REG_R0)
    r_r1 = mu.reg_read(UC_ARM_REG_R1)
    r_r2 = mu.reg_read(UC_ARM_REG_R2)
    r_pc = mu.reg_read(UC_ARM_REG_PC)
    print(">>> r0 = 0x%x" %r_r0)
    print(">>> r1 = 0x%x" %r_r1)
    print(">>> r2 = 0x%x" %r_r2)
    print(">>> pc = 0x%x" %r_pc)

    # print("\nReading data from first 512byte of the RAM at: "+hex(ram_address))
    print("==== BEGIN ====")
    ram_data = mu.mem_read(ram_address, SIZE)
    # print(str(binascii.hexlify(ram_data)))
    print("==== END ====")

    # from the reversed binary, we know which are the magic bytes
    # at the beginning of the kernel
    if b"27051956" == binascii.hexlify(bytearray(ram_data[:4])):
        print("\nMagic Bytes match :)\n\n")
        with open("kernel.bin", "wb") as f:
            f.write(ram_data)

except UcError as e:
    print("ERROR: %s" % e)
```
{% endtab %}
{% endtabs %}

<figure><img src="../../.gitbook/assets/image (10).png" alt=""><figcaption><p>Decrypted kernel header</p></figcaption></figure>

vmlinux-to-elf
