# EW04 Blank Paper

## Description

> If you did not solve EW03, buy hint #1 for the URL to this challenge.

> Author: **Derrick Png**

This challenge provides a `src.zip` file, containing the source file for the site we are to exploit in this challenge. The target URL is [EternalInternal2412.nypinfsecctf.tk](http://eternalinternal2412.nypinfsecctf.tk/), which is found in the previous challenge.

## The Challenge

The source file contains a `Client` folder, `server` folder, and a `package.json`. Firstly, let's take a look inside package.json.

### package.json

```json
{
  "name": "lodash-prototype-pollution-example",
  "version": "1.0.0",
  "description": "Prototype Pollution is a vulnerability affecting JavaScript. Prototype Pollution refers to the ability to inject properties into existing JavaScript language construct prototypes, such as objects. JavaScript allows all Object attributes to be altered, including their magical attributes such as `__proto__`, `constructor` and `prototype`. An attacker manipulates these attributes to overwrite, or pollute, a JavaScript application object prototype of the base object by injecting other values. Properties on the `Object.prototype` are then inherited by all the JavaScript objects through the prototype chain. When that happens, this leads to either denial of service by triggering JavaScript exceptions, or it tampers with the application source code to force the code path that the attacker injects, thereby leading to remote code execution.",
  "main": "index.js",
  "scripts": {
    "client": "cd Client && nodemon index.js",
    "server_dev": "cd server && npm run start",
    "dev": "concurrently \"npm run client\" \"npm run server_dev\""
  }
}
```

This basically explains the exploit that we need to perform. It is a `prototype pollution` exploit based on the old, vulnerable version of the `lodash` package in **NodeJS**.

We can first visit the website given and see what we are going to deal with.

![](https://user-images.githubusercontent.com/83258849/147675368-b670bbfe-c8be-48f9-b6ca-0dc21888cbda.png)

It's pretty empty... aside from a login page. SQL Injection doesn't work, no information under inspect element, and default credentials don't work.

![](https://user-images.githubusercontent.com/83258849/147675685-e32eea93-a3d8-4690-8098-35a2aa84dc5e.png)

Checking the files given, the files in the `server` folder does not give us much information. Under the `Client` folder however, the index.js seems to be very helpful.

We can see the lodash module that has been imported has been given the variable `_`

![cat index.js](https://user-images.githubusercontent.com/83258849/147675802-b920ddd8-2e75-4691-8b5f-0c4011d18eb1.png)

We can also see the default login credentials `user:pwd`, which we can use to successfully login to the website.

![](https://user-images.githubusercontent.com/83258849/147675908-83a35383-07cf-4988-a506-f0b905e80e76.png)

Logging in to the site, there are messages on the home page and we can create new messages.

We can also see that this user is a real gamer as he plays roblox and is proud of owning an NFT.

![](https://user-images.githubusercontent.com/83258849/147676155-aeb644f1-991b-4bbf-95eb-f491f60a3698.png)

![](https://user-images.githubusercontent.com/83258849/147676178-8a45fb63-458b-4985-8afc-70fe3126bc8f.png)

Nothing else to explore on the website and nothing suspicious so far. Going back into examining `index.js`, we can see an array of objects which are messages, 2 objects of interest have a `secret` attribute set to `true`, 1 containing a fake flag and another containing a _suspicious link_.

![](https://user-images.githubusercontent.com/83258849/147678807-6bdc71ac-75ca-4297-b800-5bd8127b95b3.png)

Here is the link [https://bit.ly/30ZzwYZ](https://bit.ly/30ZzwYZ), if u want to check it out. The creator of this challenge have greate taste!

Since the fake flag has an attribute of secret set the true, and we can't see those messages on our user home page, I assume that we have to find a way to view the messages with an attribute `secret` that has been set to `true`.

Looking at the rest of the code, specifically at the `/api/message` endpoint, the page authenticates the user, then checks `user.secret` and if the value returns true, then it will show all the messages including the ones with the `secret` attribute set to `true`. Else, it will only send the messages with the `secret` attribute not set or set to `false`.

![](https://user-images.githubusercontent.com/83258849/147678557-88976e91-54ba-43d5-853e-276670f0f6f7.png)

So now we know that we need to change the `secret` attribute of the user object to `true`, using `prototype pollution`. To exploit the site using `prototype pollution`, we can first look more into what is `prototype pollution` and how can it change the attributes of objects in JavaScript.

## What is Prototype Pollution?

If you are unaware of `prototype pollution`, it is a vulnerability that is related to the JavaScript we know and love, as opposed to php.

To understand `Prototype Pollution`, we first need to know that every JavaScript object inherits the attributes from a parent object through a property called `__proto__`.

> The Prototypal Inheritance is a feature in javascript used to add methods and properties in objects. [source](https://www.geeksforgeeks.org/prototypal-inheritance-using-\_\_proto\_\_-in-javascript/)

> `__proto__` is a way to inherit properties from an object in JavaScript. `__proto__`, a property of Object.prototype, is an accessor property that exposes the \[\[Prototype]] of the object through which it is accessed. [source](https://medium.com/dev-proto/understanding-proto-in-javascript-c5a42647f04)

Since JavaScript allows all Object attributes to be altered on the server side only if we can manipulate the values of an Object , we can alter the `__proto__` attribute of objects and effectively setting any attribute we want. This is useful in cases like when the server checks the user's attributes for authorization.

Searching for `lodash prototype pollution writeup`, I used this post as reference to exploit the target URL [https://motion-software.com/blog/prototype-pollution-in-lodash](https://motion-software.com/blog/prototype-pollution-in-lodash). You should read up on the whole post to understand more in-depth on how this exploit works.

## Performing The Exploit

From the post, we can see that the vulnerable part of the application is the `merge()` function in the vulnerable `lodash` module, and it is used in the target site as we can see it used in the `index.js` under the `Client` folder.

![](https://user-images.githubusercontent.com/83258849/147679996-4ac0e09d-86d4-4369-8a4f-d0a933046718.png)

This code is placed under the `/api/message` endpoint, with a `PUT` request. So we can guess that this code is ran when a new message is created.

Using `Burp Suite`, we login, create a new message, and check the `PUT` request that has been made to the `/api/message` endpoint.

![](https://user-images.githubusercontent.com/83258849/147681207-63103e23-006c-4520-bd04-d4d22525d204.png)

As expected, the data sent is in `json` format, which is expected for `prototype pollution` challenge.

We need to change the request data and send a payload that can change the parent object's attribute of the user object to have a secret attribute set to true, through the `__proto__` attribute.

## Crafting The Payload

Referring back to the reference post, an example payload was given where they set the `canDelete` attribute to `true`.

```
{"auth": {"name": "user", "password": "pwd"}, "message": { "text": "😈", "__proto__": {"canDelete": true}}}
```

Now we just have to change the attribute to \`secret instead and change the other variables to match the ones in our request.

### Original Request

```json
{"auth":{"name":"user","password":"pwd"},"message":{"message":"lol"}}
```

### Malicious Request Payload

```json
{"auth":{"name":"user","password":"pwd"},"message":{"message":"lol", "__proto__": {"secret": true}}}
```

Sending this payload would return the flag and a `ROT13` encoded URL for the next challenge.

![](https://user-images.githubusercontent.com/83258849/147682113-98786f75-64c8-4e02-b75f-27a731aef77f.png)

flag = `NYP{PR0T0TYPE_P011UTI0N_15_TH3_K3Y}`
