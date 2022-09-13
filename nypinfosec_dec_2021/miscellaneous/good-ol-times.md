# Good Ol Times

> Dear Secret Agent,

> Can you turn back the time, before its too late?

> Author: **Edwin**

We are provided with a jpg image `clock.jpg`

## The Challenge

If a challenge gives an image, my first instinct would be to

1. Open the image first to see if there are any clues or hidden text that are barely visible
2. Check exif data using `exiftool`
3. Use the `strings` tool to see if there are any suspicious strings
4. Use `binwalk` on the image file to check if there are any hidden files
5. Use `steghide` to check if there are any embedded/encrypted files
6. Check for hidden texts in the frames or the Least Significant Bit (LSB) using `stegsolve.jar` ([link](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)) or using [StegOnline](https://stegonline.georgeom.net/upload)
7. Check the hex and alter the file signature if necessary using `hexedit`

_The tools mentioned can all be found online._

Luckily, this challenge only requires us to use the `strings` tool, which is simple.

Running `strings clock.jpg`, a row of binary string can be seen at the very last line that has been returned.

Pasting the binary string into [CyberChef](https://gchq.github.io/CyberChef/) and decoding it from `Binary` would return another gibberish text. But we are using `CyberChef` here, so it would detect that it is Base64 encoded and we can easily decode it, which returns a pastebin url `https://pastebin.com/FPMq4qkC`.

Visiting the URL, luckily for us, it isn't another rickroll. But unfortunately, it returns a `404 not found`.

![image](https://user-images.githubusercontent.com/83258849/147764328-d122f48f-f45c-45fd-a2fe-b318ef32e26c.png)

My first thought was that this was unintended and the administrators of the pastebin website removed it because the content didn't follow their rules.

But as the saying goes, "Once on the Internet, always on the Internet" - Sun Tzu, probably not.

The challenge name and description also hints that we should "go back in time". So we should check out the [Way Back Machine](https://archive.org/web/).

The `Way Back Machine` is a database that stores old versions of websites, only if they are archived of course (not all websites have an archive on the site).

Entering the pastebin url into the `Way Back Machine`, we can see an archive has been made way back in 12 October 2021.

![image](https://user-images.githubusercontent.com/83258849/147765075-0ce7b98e-1cc9-4116-922f-919efb71bb9d.png)

Checking out the archive would give us the flag.

flag = NYP{l00king\_aT\_h!st0ry}
