# Hidden in Plain Sight

> UGH Ansi screwed up again! I wonder what sequence of events lead to this.

> Author: **Carl Voller**

`nc hidden-in-plain-sight.nypinfsecctf.tk 8002`

## The Challenge

Nothing else is given, so let's try running the `netcat` command.

![image](https://user-images.githubusercontent.com/83258849/147765426-c011ae78-657a-4fbb-9b34-5f95e7b77bb1.png)

Not very helpful...

Let's try finding out more information on this port that we are trying to connect. I will be using `nmap`

`nmap -sC -sV -p 8002 hidden-in-plain-sight.nypinfsecctf.tk`

This command is to scan with default scripts (`-sC`) and enumerate the versions of the service running (`-sV`) on the port 8002 (`-p 8002`).

And immediately, we see our flag.

![image](https://user-images.githubusercontent.com/83258849/147765838-297e276b-cfbb-44b8-8be6-a93bdeb5877e.png)

flag = `NYP{ans1_c0ntr0l_s3qu3nc3s_damn_c00l}`

This is probably not the intended way to solve this, so I would be happy to hear the intended solution :)
