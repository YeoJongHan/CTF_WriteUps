# Want a byte?
## Description
> Scrolling through my projects, I found some old project code. I remember this code had some "backdoors". But since I mistakenly deleted utils.py, now I cannot understand my own code! Can you help me make sense out of it? You will be rewarded with a flag for your help.

- [main.py](https://github.com/YeoJongHan/CTF_WriteUps/blob/main/STANDCON_2022/Reverse/Want%20a%20byte%3F/challenge/main.py)
- [utils.pyc](https://github.com/YeoJongHan/CTF_WriteUps/blob/main/STANDCON_2022/Reverse/Want%20a%20byte%3F/challenge/utils.pyc)

## Solution
### TL;DR
- Decompile utils.pyc
- Find out that master_key is always 'a'\*20
- Notice its just encrypting the flag by xoring each character of the flag with 'a's
- Xor the encrypted flag with 'a's
- Win flag
#
### Analysis
We have to first decompile [utils.pyc](https://github.com/YeoJongHan/CTF_WriteUps/blob/main/STANDCON_2022/Reverse/Want%20a%20byte%3F/challenge/utils.pyc) to understand the functions that resides in it.

Using `decompyle3`, it indicates that the file is coded in Python2.7. This guy really needs to upgrade his Python.

<img src="https://user-images.githubusercontent.com/83258849/174642595-3dedee4a-c3f6-4164-83d7-8c2b71c1f29c.png" width="700" height="200">

For Python2.7, we can use `uncompyle6`.

<img src="https://user-images.githubusercontent.com/83258849/174642733-956014cc-62d3-47d2-9fe2-e1ea5797e43c.png" width="600" height="300">

> Note, some of you might have trouble installing uncompyle6 or decompyle3. I faced similar issues and managed to get it to work. If you help, just give me a dm on discord :)

