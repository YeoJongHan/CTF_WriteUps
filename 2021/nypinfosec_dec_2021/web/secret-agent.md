# Secret Agent

## Description

> Dear secret agent, Can you find the flag?

> Author: **Edwin**

> http://secret-agent.nypinfsecctf.tk/

## The Challenge

Visiting the link provided, the page is really blank with nothing much.

![image](https://user-images.githubusercontent.com/83258849/147807592-f5855bad-bc33-4e9a-96fe-bfd51138b92c.png)

Opening `Insepct Element` we can see two hidden messages.

![image](https://user-images.githubusercontent.com/83258849/147807648-7bf32a9f-b1e8-4f13-8da0-7c0bed64b876.png)

The first message is clearly in hex.

```html
<!-- 54 72 79 20 63 68 65 63 6b 69 6e 67 20 2f 66 6c 61 67 -->
```

Putting it in CyberChef, it decodes and asks us to try visiting the `/flag` endpoint.

![image](https://user-images.githubusercontent.com/83258849/147807720-4d6b5854-7941-489a-adc5-b944347f642a.png)

However, visiting `http://secret-agent.nypinfsecctf.tk/flag` just redirects us back the to main page. What's going on here? There may be a check on the server side that checks if a specific condition is satisfied, like an authentication feature. Since we don't know what the condition to be satisfied is, we have to continue enumerating the site.

Let's check out the second message. Decoding from binary, it returns us `User Agent Chris Says there is nothing suspicious!!!`. Seems like this challenge has something to do with changing the `User Agent` of the request made to `/flag` endpoint. The `User Agent` field in a `HTTP` request is to indicate what web browser and the version of the browser the user is using to access the site. [source](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent)

I tried changing the `User Agent` to `Chris` using `Burp Suite` but it didn't work. This challenge got me quite stumped as it didn't really give any more info, but I looking back, the binary message that hints at changing the `User Agent` is found in the `alt` attribute of the image. Let's try to save the image and see if there are any information hidden in the image. Hiding useful information is normal in most CTF web challenges, so you should keep note of that.

Checking the metadata (exif data) of the image using `exiftool`, we immediately see what looks like a `Base64` encoded message in the `Author` field.

![image](https://user-images.githubusercontent.com/83258849/147808137-76353c1a-555d-4edf-a079-3929529148c0.png)

Decoding it from `Base64`, we can see the `User-Agent` value that we are meant to set.

![image](https://user-images.githubusercontent.com/83258849/147808346-53e1367f-c89c-42a2-ada4-df9b1375c53f.png)

Setting the `User Agent` to `sUp3R-s3crXt-aG3nT` and sending the request through `Burp Suite's Repeater` to the `/flag` endpoint, we get our flag.

![image](https://user-images.githubusercontent.com/83258849/147808425-b44641bc-1cff-4ec2-b0b2-40bbe95583eb.png)

flag = `NYP{h3y_h0w_d1d_u_f!nd_th!s}`
