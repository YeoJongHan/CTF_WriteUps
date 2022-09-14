# Spam Mail

## Description

> Secret agent, you received this encrypted mail from john. Decipher the spam mail to find the flag.

> Author: **Xin Ying**

A `spam.zip` file comes along with the challenge.

## The Challenge

We are given a zip file and viewing the contents with `WinRar`, it doesn't seem like its harmful to unzip it.

![image](https://user-images.githubusercontent.com/83258849/147811985-c72d0276-34e5-467f-a82e-bf5cfff14249.png)

If we try to unzip it, there will be a prompt for a password. We do not know what the password is... so let's try cracking it with `John The Ripper`.

### Getting a hash for John to crack

Ensure that you have `john` installed, if not you can try running `sudo apt-get install john` to install it(if you are working on a `Debian` distro)

We need a hash for `john` to crack. We can use `zip2john`, which would come along once you installed `john`, to get the hash of the zip file.

Run `zip2john spam.zip > forjohn`. This command would output the hash into a file called `forjohn`, which we will feed to `john` to crack.

The hash returned would look something like this:

![image](https://user-images.githubusercontent.com/83258849/147812242-bf4cac11-19be-4bb7-ae32-3bc43636ddd0.png)

### Cracking hash with John

We can now use `john` to crack the hash to find the password. Run the command `john forjohn --wordlist=<path to wordlist>`. I used the `rockyou.txt` wordlist, which would contain the passwords that is used in most CTF challenges.

The cracking should be complete nearly instantly

![image](https://user-images.githubusercontent.com/83258849/147812383-8a604efe-9040-46d8-918a-00d961f04839.png)

To view the cracked password, run the command `john forjohn --show`.

![image](https://user-images.githubusercontent.com/83258849/147812441-2fc023d3-ba59-4476-97e4-be3f132e4e78.png)

The password that has been cracked is `winter`. Let's use that password to decrypt and extract the file in `spam.zip`.

A `spam.txt` is extracted and viewing the contents, it looks the contents of a phishing email that you would receive from an email with the name of "yourLongLostBestFriend@notscam.com".

![image](https://user-images.githubusercontent.com/83258849/147812639-b05fb62a-1628-425f-a8bc-2c0fef0590b9.png)

Look's like there is nothing more than this long string of text, so let's try to search it online for more information on what this text actually is. We can pick out a line that looks unique in the text. I'll be searching for `Senate bill 2716 ; Title 3 , Section 308`. The first result returned already indicates that it is some kind of encoded message in the form of a spam https://www.vbforums.com/showthread.php?157720-Decode-the-SPAM.

Visiting the decode site provided, http://www.spammimic.com/decode.shtml, and pasting in the whole spam text to decode, we get our flag!

![image](https://user-images.githubusercontent.com/83258849/147812823-4d8b003d-bef6-4623-9310-13fb3deead52.png)

flag = `NYP{D0NT_D3L3T3_TH3_SP@M}`
