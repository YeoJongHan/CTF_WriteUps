# Secret Conversation

## Description

> Dear Secret Agent,

> We have managed to wiretapped EternalWinter conversation, however the file got corrupted while we are transfering the information!

> Can you get any information out of it?

> Author: **Edwin**

A `Secret_Conversation.png` file is attached to this challenge.

## The Challenge

Trying to open the file indicates an error, so either the **file is corrupted**, or it is **not a png file**.

![image](https://user-images.githubusercontent.com/83258849/147769049-3451adb0-490b-440c-94fc-8ab868ec90ba.png)

Running `file Secret_Conversation.png` in a Linux OS, we can clearly see that it isn't a png file like it's extension stated... Seems pretty _sus_ to me >\_>

![image](https://user-images.githubusercontent.com/83258849/147769432-e74f5cce-775d-42f1-8212-cf099cef2117.png)

Since the tool states that there are `ASCII text` in the file, let's try to `cat` it out to view the ASCII text.

![image](https://user-images.githubusercontent.com/83258849/147769645-733fc535-c93a-4187-8b7a-f4bdd0764be4.png)

Checking the first few lines, we can make out that it is an email file. Lets change the extension of the file to `.eml`.

Reading the email content indicates that there is an attachment encoded in Base64, so let's try to extract the attachment.

![image](https://user-images.githubusercontent.com/83258849/147769851-b8985942-c24e-47c8-a08f-39cc4b871a72.png)

There are several ways to extract the attachment, but I used the tool `munpack` to extract the attachment as it is quick and easy: `munpack Secret_Conversation.eml`

A file named `secret` is extracted.

![image](https://user-images.githubusercontent.com/83258849/147770204-c7066d17-a9a6-405e-a280-0f919ece6428.png)

Running `file secret` returns that it is a "`PAK archive data`", but it is lying.

Checking the `file signature` bytes using a hex editor, there is an "`IHDR`" at the first few bytes. IHDR is in the headers of png files.

![image](https://user-images.githubusercontent.com/83258849/147770377-12170b1f-67f9-41eb-918f-fe9015623421.png)

You can search up `IHDR` file and a bunch of links pointing to `PNG` would be the result.

To fix the file, we need to change the first few bytes of the file to that of a PNG (change to the correct file signature).

Using the hex editor, change the first `16` bytes of the `secret` file to that of a PNG file. You can open the hex editor on a working PNG file for reference, but I used this [site](https://asecuritysite.com/forensics/png?file=%2Flog%2Fbasn0g01.png).

Save the changes and open the file and we get our flag.

![image](https://user-images.githubusercontent.com/83258849/147771516-ab281d4e-e2a7-4281-a9a4-9ab61d6d3f02.png)

flag = `NYP{R34dIngaTTaCHm3nT!}`
