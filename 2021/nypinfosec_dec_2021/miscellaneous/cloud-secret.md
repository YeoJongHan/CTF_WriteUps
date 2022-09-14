# Cloud Secret

## Description

> Dear Secret Agent,

> You have found a secret portal to the cloud service, are you able to find the secret?

> Author: **Edwin**

A link was provided with this challenge: [http://cloud-secret.nypinfsecctf.tk](http://cloud-secret.nypinfsecctf.tk)

## The Challenge

Visiting the site, it's just a scuffed login page.

![image](https://user-images.githubusercontent.com/83258849/147761101-7147f783-7745-4111-a595-006bce2229d8.png)

Viewing the page source code, it looks like the form does not do anything at all.

Since the challenge name is `Cloud Secret`, it indicates that this is some kind of cloud challenge...

Looking back at the page source code, we can see that under the `<body>` element, the image of the background is taken from an `amazon s3 bucket`, which is a URL usually containing `s3.amazonaws.com`.

```html
<img src="https://nypctf.s3.ap-southeast-1.amazonaws.com/logo-resp.svg" alt="dHJ5IGZpbmRpbmcgZmxhZy50eHQ" style="height:40px;width:160px;">
```

An `amazon s3 bucket` is like a cloud storage for files:

> To upload your data (photos, videos, documents, etc.) to Amazon S3, you must first create an S3 bucket in one of the AWS Regions. You can then upload any number of objects to the bucket. ([source](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingBucket.html#access-bucket-intro))

Here is more information on amazon buckets if you want to read up on them [https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingBucket.html#access-bucket-intro](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingBucket.html#access-bucket-intro)

Visiting `https://nypctf.s3.ap-southeast-1.amazonaws.com` will return an error message

![image](https://user-images.githubusercontent.com/83258849/147762374-4606f918-1cee-45c8-99d7-6dc7fe6401d2.png)

Checking the `alt` attribute of the image again, we can see that it looks like it is either gibberish or encoded, most likely encoded as the `alt` attribute is to display alternative information for the image if it fails to load.

```html
<img src="https://nypctf.s3.ap-southeast-1.amazonaws.com/logo-resp.svg" alt="dHJ5IGZpbmRpbmcgZmxhZy50eHQ" style="height:40px;width:160px;">
```

So we can try putting it in [CyberChef](https://gchq.github.io/CyberChef/) and it returns `try finding flag.txt` when decoded with with `Base64`.

Let's go back to the `amazon s3 bucket` and try accessing the `/flag.txt` endpoint `https://nypctf.s3.ap-southeast-1.amazonaws.com/flag.txt`.

And we have our flag!

flag = `NYP{v13wing_th3_cl0uD}`
