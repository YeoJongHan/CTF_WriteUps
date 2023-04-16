# Private Assertion Nexus

| Difficulty | Points |
| ---------- | ------ |
| Easy       | 150    |

## Description

> I've heard talk about a simple method of communication, but I'm not sure what it is. Luckily I found some traffic of the said communication, but I'm too noob to figure it out. Please help me crack this enigma of a transmission.

{% file src="../../../.gitbook/assets/traffic.pcap" %}

## Solution

### TL;DR

1. Find the correct sourcecode which leads to the key mappings.
2. Decrypt the l2cap packets.
3. Stonks

### Analysis

Viewing the packets captured, we mostly see garbage data that are not relevant to solving the challenge.

<figure><img src="../../../.gitbook/assets/image (5).png" alt=""><figcaption><p>Garbage Data 1</p></figcaption></figure>

We can see that the first few packets are mostly configuration packets and can put these aside first.

<figure><img src="../../../.gitbook/assets/image (21).png" alt=""><figcaption><p>Garbagde Data 2</p></figcaption></figure>

Followed by these long chain of `USB_INTERRUPT` packets, which can can also put aside and come back to them later if needed.

Scrolling down, we suddenly see a bunch of `L2CAP` packets.

<figure><img src="../../../.gitbook/assets/image (10) (1).png" alt=""><figcaption><p>L2CAP Packets</p></figcaption></figure>

We can filter to see only these packets by entering `btl2cap` in the filter bar.

<figure><img src="../../../.gitbook/assets/image (9) (1).png" alt=""><figcaption><p>Filtering L2CAP packets</p></figcaption></figure>

Searching online, we can see that `L2CAP` packets are used for Bluetooth communication.

<figure><img src="../../../.gitbook/assets/image (11).png" alt=""><figcaption><p>Purpose of L2CAP Packets</p></figcaption></figure>

This indicates that there may be potential data that we can decode in these packets, so let's spend some time looking into it.

Expanding the `Bluetooth L2CAP Protocol` field in Wireshark, we can see that every single `L2CAP` packet has the payload starting with `a1`

<figure><img src="../../../.gitbook/assets/image (1) (2).png" alt=""><figcaption><p>L2CAP Protocol Field</p></figcaption></figure>

This might be a header specific to this kind of Bluetooth device, so we can try looking it up.

### Decoding L2CAP Packets

Searching for the keywords `bluetooth l2cap a1 payload` on Google, we come across a [CTF writeup](https://ctftime.org/writeup/33625) on a similar challenge.

Taken from the writeup:

> Let's look at one of the payloads from the pcap: `a10201ff0300`
>
> Comparing with the above code or image, we can decipher that the `a1` byte is the value denoting this is a data packet. `02` is the ID for a mouse...

An example payload we have is `a1010200000000000000`. We have the `a1` the same, but since the second byte they have is `02` which represents the ID for a mouse, our payload has `01`, which should represent the ID for a keyboard.

There is also a reference to a source code provided by the author of the writeup:

> Another good place for packet structure is lines 174-182 of [https://github.com/benizi/hidclient/blob/master/hidclient.c](https://github.com/benizi/hidclient/blob/master/hidclient.c)

Looking at the source code on lines 184-190 for our keyboard payload struct, we can see that our payload matches the struct.

```c
struct hidrep_keyb_t
{
	unsigned char	btcode; // Fixed value for "Data Frame": 0xA1
	unsigned char	rep_id; // Will be set to REPORTID_KEYBD for "keyboard"
	unsigned char	modify; // Modifier keys (shift, alt, the like)
	unsigned char	key[8]; // Currently pressed keys, max 8 at once
} __attribute((packed));
```

I'm not sure why but the source code defines the ID for keyboard as 2 instead (lines 139-141):

```c
// These numbers must also be used in the HID descriptor binary file
#define	REPORTID_MOUSE	1
#define	REPORTID_KEYBD	2
```

Looking back at the keyboard struct, we see that the 3rd byte represents the `modifier keys`, then the rest of the bytes represents the keys pressed.

Scrolling down the source code to lines 826-956, we see that we have the modifier keys and values that represents the keys pressed:

```c

			  // *** "Modifier" key events
			  case	KEY_RIGHTMETA:
				u <<= 1;
			  case	KEY_RIGHTALT:
				u <<= 1;
			  case	KEY_RIGHTSHIFT:
				u <<= 1;
			  case	KEY_RIGHTCTRL:
				u <<= 1;
			  case	KEY_LEFTMETA:
				u <<= 1;
			  case	KEY_LEFTALT:
				u <<= 1;
			  case	KEY_LEFTSHIFT:
				u <<= 1;
			  case	KEY_LEFTCTRL:
				evkeyb->btcode = 0xA1;
				evkeyb->rep_id = REPORTID_KEYBD;
				memcpy ( evkeyb->key, pressedkey, 8 );
				modifierkeys &= ( 0xff - u );
				if ( inevent->value >= 1 )
				{
					modifierkeys |= u;
				}
				evkeyb->modify = modifierkeys;
				j = send ( sockdesc, evkeyb,
					sizeof(struct hidrep_keyb_t),
					MSG_NOSIGNAL );
				if ( 1 > j )
				{
					return	-1;
				}
				break;
			  // *** Regular key events
			  case	KEY_KPDOT:	++u; // Keypad Dot ~ 99
			  case	KEY_KP0:	++u; // code 98...
			  case	KEY_KP9:	++u; // countdown...
			  case	KEY_KP8:	++u;
			  case	KEY_KP7:	++u;
			  case	KEY_KP6:	++u;
			  case	KEY_KP5:	++u;
			  case	KEY_KP4:	++u;
			  case	KEY_KP3:	++u;
			  case	KEY_KP2:	++u;
			  case	KEY_KP1:	++u;
			  case	KEY_KPENTER:	++u;
			  case	KEY_KPPLUS:	++u;
			  case	KEY_KPMINUS:	++u;
			  case	KEY_KPASTERISK:	++u;
			  case	KEY_KPSLASH:	++u;
			  case	KEY_NUMLOCK:	++u;
			  case	KEY_UP:		++u;
			  case	KEY_DOWN:	++u;
			  case	KEY_LEFT:	++u;
			  case	KEY_RIGHT:	++u;
			  case	KEY_PAGEDOWN:	++u;
			  case	KEY_END:	++u;
			  case	KEY_DELETE:	++u;
			  case	KEY_PAGEUP:	++u;
			  case	KEY_HOME:	++u;
			  case	KEY_INSERT:	++u;
						++u; //[Pause] key
						// - checked separately
			  case	KEY_SCROLLLOCK:	++u;
			  case	KEY_SYSRQ:	++u; //[printscr]
			  case	KEY_F12:	++u; //F12=> code 69
			  case	KEY_F11:	++u;
			  case	KEY_F10:	++u;
			  case	KEY_F9:		++u;
			  case	KEY_F8:		++u;
			  case	KEY_F7:		++u;
			  case	KEY_F6:		++u;
			  case	KEY_F5:		++u;
			  case	KEY_F4:		++u;
			  case	KEY_F3:		++u;
			  case	KEY_F2:		++u;
			  case	KEY_F1:		++u;
			  case	KEY_CAPSLOCK:	++u;
			  case	KEY_SLASH:	++u;
			  case	KEY_DOT:	++u;
			  case	KEY_COMMA:	++u;
			  case	KEY_GRAVE:	++u;
			  case	KEY_APOSTROPHE:	++u;
			  case	KEY_SEMICOLON:	++u;
			  case	KEY_102ND:	++u;
			  case	KEY_BACKSLASH:	++u;
			  case	KEY_RIGHTBRACE:	++u;
			  case	KEY_LEFTBRACE:	++u;
			  case	KEY_EQUAL:	++u;
			  case	KEY_MINUS:	++u;
			  case	KEY_SPACE:	++u;
			  case	KEY_TAB:	++u;
			  case	KEY_BACKSPACE:	++u;
			  case	KEY_ESC:	++u;
			  case	KEY_ENTER:	++u; //Return=> code 40
			  case	KEY_0:		++u;
			  case	KEY_9:		++u;
			  case	KEY_8:		++u;
			  case	KEY_7:		++u;
			  case	KEY_6:		++u;
			  case	KEY_5:		++u;
			  case	KEY_4:		++u;
			  case	KEY_3:		++u;
			  case	KEY_2:		++u;
			  case	KEY_1:		++u;
			  case	KEY_Z:		++u;
			  case	KEY_Y:		++u;
			  case	KEY_X:		++u;
			  case	KEY_W:		++u;
			  case	KEY_V:		++u;
			  case	KEY_U:		++u;
			  case	KEY_T:		++u;
			  case	KEY_S:		++u;
			  case	KEY_R:		++u;
			  case	KEY_Q:		++u;
			  case	KEY_P:		++u;
			  case	KEY_O:		++u;
			  case	KEY_N:		++u;
			  case	KEY_M:		++u;
			  case	KEY_L:		++u;
			  case	KEY_K:		++u;
			  case	KEY_J:		++u;
			  case	KEY_I:		++u;
			  case	KEY_H:		++u;
			  case	KEY_G:		++u;
			  case	KEY_F:		++u;
			  case	KEY_E:		++u;
			  case	KEY_D:		++u;
			  case	KEY_C:		++u;
			  case	KEY_B:		++u;
			  case	KEY_A:		u +=3;	// A =>  4
```

We can automate this using a script to make things easier for us. We can do so using the `pyshark` library in Python.

Firstly, we need to extract the payload from the L2CAP packets.

<details>

<summary>extract.py</summary>

```python
import pyshark

f = pyshark.FileCapture('traffic.pcap', display_filter="btl2cap")

keys = []
for p in f:
    data = p['btl2cap'].payload.split(":")
    print(data)
```

</details>

<figure><img src="../../../.gitbook/assets/image (25).png" alt=""><figcaption><p>Extracted output</p></figcaption></figure>

We can then filter the packets where only our 2nd byte is equal to `01`, and then check if the 3rd byte is `02` as having the third byte as `02` means a `LEFT SHIFT` is pressed (according to the source code).

We then see that the other bytes are all null except for the 4th byte, so we can guess that that is our value representing the key pressed.

So we can grab the 4th byte, check what character it represents (A=4, B=5, C=6 and so on...), and substitute it for the corresponding character, and check the 2nd byte to see if the LEFT SHIFT key is pressed.

{% tabs %}
{% tab title="solve.py" %}
```python
import pyshark

# Reference: https://github.com/benizi/hidclient/blob/master/hidclient.c#L811
key_mappings = '''case	KEY_F12:	++u;
case	KEY_F11:	++u;
case	KEY_F10:	++u;
case	KEY_F9:		++u;
case	KEY_F8:		++u;
case	KEY_F7:		++u;
case	KEY_F6:		++u;
case	KEY_F5:		++u;
case	KEY_F4:		++u;
case	KEY_F3:		++u;
case	KEY_F2:		++u;
case	KEY_F1:		++u;
case	KEY_CAPSLOCK:	++u;
case	KEY_SLASH:	++u;
case	KEY_DOT:	++u;
case	KEY_COMMA:	++u;
case	KEY_GRAVE:	++u;
case	KEY_APOSTROPHE:	++u;
case	KEY_SEMICOLON:	++u;
case	KEY_102ND:	++u;
case	KEY_BACKSLASH:	++u;
case	KEY_RIGHTBRACE:	++u;
case	KEY_LEFTBRACE:	++u;
case	KEY_EQUAL:	++u;
case	KEY_MINUS:	++u;
case	KEY_SPACE:	++u;
case	KEY_TAB:	++u;
case	KEY_BACKSPACE:	++u;
case	KEY_ESC:	++u;
case	KEY_ENTER:	++u;
case	KEY_0:		++u;
case	KEY_9:		++u;
case	KEY_8:		++u;
case	KEY_7:		++u;
case	KEY_6:		++u;
case	KEY_5:		++u;
case	KEY_4:		++u;
case	KEY_3:		++u;
case	KEY_2:		++u;
case	KEY_1:		++u;
case	KEY_Z:		++u;
case	KEY_Y:		++u;
case	KEY_X:		++u;
case	KEY_W:		++u;
case	KEY_V:		++u;
case	KEY_U:		++u;
case	KEY_T:		++u;
case	KEY_S:		++u;
case	KEY_R:		++u;
case	KEY_Q:		++u;
case	KEY_P:		++u;
case	KEY_O:		++u;
case	KEY_N:		++u;
case	KEY_M:		++u;
case	KEY_L:		++u;
case	KEY_K:		++u;
case	KEY_J:		++u;
case	KEY_I:		++u;
case	KEY_H:		++u;
case	KEY_G:		++u;
case	KEY_F:		++u;
case	KEY_E:		++u;
case	KEY_D:		++u;
case	KEY_C:		++u;
case	KEY_B:		++u;
case	KEY_A:		u +=3;'''
keymaps = {}
key_mappings = key_mappings.split("\n")[::-1]

keys_found = [x.split("_")[1].split(":")[0] for x in key_mappings]
for i in range(4,len(key_mappings)+4):
    keymaps[i] = keys_found[i-4]

f = pyshark.FileCapture('traffic.pcap', display_filter="btl2cap")

keys = []
for p in f:
    data = p['btl2cap'].payload.split(":")
    key = ""
    if data[1] == "01":
        if data[4] != "00":
            if data[2] == "02":
                key += "SHIFT "
            key += keymaps[int(data[4],16)].lower()
            keys.append(key)
            
for i,line in enumerate(keys):
    keys[i] = line.split()[-1].upper() if "SHIFT" in line else line
    if keys[i] == "LEFTBRACE":
        keys[i] = "{"
    elif keys[i] == "RIGHTBRACE":
        keys[i] = "}"
    elif keys[i] == "MINUS":
        keys[i] = "_"
print(''.join(keys))
```
{% endtab %}
{% endtabs %}
