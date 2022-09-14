# EW02 Framed Copy

## Description

> The EternalWinter Payment website is also used to send confidential information to their operatives. To see the secret content, you will have to use a different FRAME of mind, a different FRAME of reference, and a different FRAME of a webpage.

> Quickly! Solve this challenge before EternalWinter FRAMES you for the attack!

> Author: **Carl Voller**

## The Challenge

This challenge wants us to visit a website.

From the file given in previous challenge, we can roughly make out a website address in `PosterIntro.png`. ![web2](https://user-images.githubusercontent.com/83258849/147629273-688b28e0-2315-4072-8bed-fec781706904.png) ![web1](https://user-images.githubusercontent.com/83258849/147629278-24c07398-826a-44ca-ae3d-a746933e152e.png)

Visiting the website gives us this page:

![Picture1](https://user-images.githubusercontent.com/83258849/147629385-b7ea7779-2e8f-477c-ab9c-d336229c7a88.png)

We should note the error message: `Error: Page accessed incorrectly. Secret flag not delivered`.

Checking back at the Challenge Description, they mentioned `FRAME` many times, hinting us to do something with frames. Searching for `frames web ctf` on Google, we can see that there are other writeups on web challenges that are related to frames. [https://blog.pspaul.de/posts/facebook-ctf-2019-secret-note-keeper/](https://blog.pspaul.de/posts/facebook-ctf-2019-secret-note-keeper/).

> I quickly checked if there was a X-Frame-Options header, but there was none. This meant we could load a search in an iFrame...

Checking the response header through `Burp Suite`, we can see that there is no `X-Frame-Option` set. This means that we can try putting it into an `<iframe>`.

![Untitled-2](https://user-images.githubusercontent.com/83258849/147630771-9799e285-0dcb-4ce7-8793-7e81dcbb59a1.png)

We can create a quick `<iframe>` with `src` set to the URL of the page in a `.html` file.

### frame.html

```html
<iframe src="https://welcome2winter2512.nypinfsecctf.tk/" title="Eternal" height="100%" width="100%"></iframe>
```

Opening the file locally,

![iframe](https://user-images.githubusercontent.com/83258849/147631248-06843ac9-b010-416a-9783-aa882c1423b6.png)

There is no error message now but it now says `This website has no flag. But it once had a perfect copy.`

My first instinct was to check the `Way Back Machine` as it states "`once had a perfect copy`", but there were no past records of the site. This means that there may be a JavaScript running which set the flag on the page then removes it instantly.

Opening and checking the response using `Burp Suite`, the flag can be seen in the value of an `<input>` element, which got removed when the JavaScript was loaded on our web browser. That's why we couldn't just use `Inspect Element` on the page itself to view the code.

![response](https://user-images.githubusercontent.com/83258849/147632258-072e1866-3431-4caf-88e1-085b578ff613.png)

flag = `NYP{Zer0K3lvinSt4rts}`
