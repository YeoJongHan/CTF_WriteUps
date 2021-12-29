# Description
> You have obtained a document from the last challenge. Where is the hidden message?

> Author: **Mark Bosco**

From the previous challenge, the flag came together with a Google Drive link `https://drive.google.com/file/d/1W3hbptocFRLciWU2ubfhJUxvt0An8TaK/view`.

Download the file `EternalOperativeGuide.pdf`

## The Challenge
Opening the pdf file would not return us any useful information.

Using `exiftool`, we can see a hint is provided in `base64` encoding.

![exif](https://user-images.githubusercontent.com/83258849/147632940-3041f33a-03c0-4bfa-8687-1711643d99c0.png)

Decoding the hint in terminal, it asks us to `export JS from pdf`. So we have to export JavaScript from the pdf file.

![decode](https://user-images.githubusercontent.com/83258849/147633058-5666291d-36c0-46bf-bcd3-89690a8eaa5e.png)

Searching on Google for `tools to export javascript from pdf`, a solution can be found on stackoverflow. [https://stackoverflow.com/questions/29342542/how-can-i-extract-a-javascript-from-a-pdf-file-with-a-command-line-tool](https://stackoverflow.com/questions/29342542/how-can-i-extract-a-javascript-from-a-pdf-file-with-a-command-line-tool)

It says that we can use the command line tool `pdfinfo -js <filename>` to extract JavaScript from a pdf. `pdfinfo` should already be installed by default on Linux distros. Otherwise, you can refer to the official (github repository)[https://github.com/howtomakeaturn/pdfinfo] on how to install it for the distro that you are using.

