# EW03 Private Document

## Description

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

It says that we can use the command line tool `pdfinfo` to extract JavaScript from a pdf. `pdfinfo` should already be installed by default on Linux distros. Otherwise, you can refer to the official (github repository)\[https://github.com/howtomakeaturn/pdfinfo] on how to install it for the distro that you are using.

Now we run `pdfinfo -js EternalOperativeGuide.pdf` to extract the JavaScript.

![pdfinfo](https://user-images.githubusercontent.com/83258849/147633880-5a5bdb90-b8e9-409d-85ed-a7640f8e6cd9.png)

Running a JavaScript Beautifier online with the script would format the code for easier readability:

```javascript
function _0x2e4f(_0x1912a5, _0x177ed5) {
    var _0x19ea99 = _0x19ea();
    return _0x2e4f = function(_0x2e4f1b, _0x2f0f6a) {
        _0x2e4f1b = _0x2e4f1b - 0x7e;
        var _0xfabe63 = _0x19ea99[_0x2e4f1b];
        return _0xfabe63;
    }, _0x2e4f(_0x1912a5, _0x177ed5);
}(function(_0x500e78, _0x3e375e) {
    var _0x5287e9 = _0x2e4f,
        _0x4e4919 = _0x500e78();
    while (!![]) {
        try {
            var _0x36e375 = -parseInt(_0x5287e9(0x82)) / 0x1 * (-parseInt(_0x5287e9(0x83)) / 0x2) + parseInt(_0x5287e9(0x87)) / 0x3 * (-parseInt(_0x5287e9(0x7e)) / 0x4) + parseInt(_0x5287e9(0x81)) / 0x5 * (-parseInt(_0x5287e9(0x85)) / 0x6) + parseInt(_0x5287e9(0x80)) / 0x7 * (-parseInt(_0x5287e9(0x7f)) / 0x8) + parseInt(_0x5287e9(0x88)) / 0x9 + parseInt(_0x5287e9(0x84)) / 0xa + parseInt(_0x5287e9(0x89)) / 0xb * (-parseInt(_0x5287e9(0x86)) / 0xc);
            if (_0x36e375 === _0x3e375e) break;
            else _0x4e4919['push'](_0x4e4919['shift']());
        } catch (_0x4f0095) {
            _0x4e4919['push'](_0x4e4919['shift']());
        }
    }
}(_0x19ea, 0xe1121));
if (0x1 == 0x0) {
    var APJX = '{' + '0' + RegExp()['c' + 'o' + 'n' + 's' + 't' + 'r' + 'u' + 'c' + 't' + 'o' + 'r']['n' + 'a' + 'm' + 'e'][+!+[] + +!+[] + (+!+[] + (+!+[] + +!+[]))] + ([] + [] + [][
        []
    ])[+!+[] + (+!+[] + +!+[])] + (!![] + [])[+!+[]] + (![] + [])[+!+[]] + (!![] + [])[+[]] + ([] + [] + [][
        []
    ])[+[+!+[] + [+[]]] / (+!+[] + +!+[])] + '0' + ([] + [] + [][
        []
    ])[+!+[]] + (typeof ![])[+!+[]] + ([] + [] + []['c' + 'o' + 'n' + 's' + 't' + 'r' + 'u' + 'c' + 't' + 'o' + 'r'])[+[+!+[] + [+[] + [+[]]]] / (+!+[] + +!+[]) / (+!+[] + +!+[]) - +!+[]] + '3' + (!![] + [])[+!+[]] + ([] + [] + [][
        []
    ])[+!+[] + +!+[]] + (!![] + [])[+!+[]] + ([] + [] + [][
        []
    ])[+[+!+[] + [+[]]] / (+!+[] + +!+[])] + ([] + [] + []['c' + 'o' + 'n' + 's' + 't' + 'r' + 'u' + 'c' + 't' + 'o' + 'r'])[+[+!+[] + [+[] + [+[]]]] / (+!+[] + +!+[]) / (+!+[] + +!+[]) - +!+[]] + ([] + [] + [][
        []
    ])[+!+[] + (+!+[] + +!+[])] + '}';

    function _0x28a2(_0x17dc92, _0x14cecc) {
        var _0x5e3b2f = _0x3636();
        return _0x28a2 = function(_0x2b466e, _0x14dda4) {
            _0x2b466e = _0x2b466e - 0x1bf;
            var _0x4ca4f4 = _0x5e3b2f[_0x2b466e];
            return _0x4ca4f4;
        }, _0x28a2(_0x17dc92, _0x14cecc);
    }

    function _0x3636() {
        var _0x18826a = ['3' + '0' + 'W' + 'x' + 'i' + 'M' + 'L' + 'B', '8' + '1' + '6' + '5' + '3' + '7' + '7' + 'Q' + 'U' + 'l' + 'P' + 'L' + 'g', '1' + '0' + 'G' + 'C' + 'q' + 'm' + 'V' + 'v', '1' + '5' + '7' + 'm' + 'P' + 'I' + 'x' + 'I' + 'K', '2' + '7' + '4' + '2' + '0' + '2' + '4' + 'g' + 'w' + 'k' + 'O' + 'R' + 'i', '1' + '5' + '2' + '7' + '6' + '1' + '0' + 't' + 's' + 'B' + 'v' + 'L' + 'n', '2' + '9' + '0' + '7' + '6' + '5' + 'E' + 'q' + 'k' + 'f' + 'L' + 'I', '9' + '4' + '5' + '5' + '4' + '8' + 'p' + 'P' + 'N' + 'M' + 'e' + 'F', '2' + '8' + '4' + '6' + 'b' + 'X' + 'I' + 'p' + 'r' + 'p', '3' + 'L' + 'a' + 'I' + 'z' + 'O' + 'P', '3' + '6' + '9' + '0' + '7' + '7' + '4' + 'a' + 'F' + 'u' + 'G' + 'P' + 'a'];
        return _0x3636 = function() {
            return _0x18826a;
        }, _0x3636();
    }(function(_0x2715f1, _0x23377b) {
        var _0x2446d9 = _0x28a2,
            _0x20c888 = _0x2715f1();
        while (!![]) {
            try {
                var _0x2f2e48 = -parseInt(_0x2446d9(0x1c0)) / 0x1 * (-parseInt(_0x2446d9(0x1c5)) / 0x2) + parseInt(_0x2446d9(0x1c6)) / 0x3 * (parseInt(_0x2446d9(0x1c4)) / 0x4) + parseInt(_0x2446d9(0x1c3)) / 0x5 * (parseInt(_0x2446d9(0x1c8)) / 0x6) + parseInt(_0x2446d9(0x1c2)) / 0x7 + -parseInt(_0x2446d9(0x1c1)) / 0x8 + parseInt(_0x2446d9(0x1c7)) / 0x9 * (parseInt(_0x2446d9(0x1bf)) / 0xa) + -parseInt(_0x2446d9(0x1c9)) / 0xb;
                if (_0x2f2e48 === _0x23377b) break;
                else _0x20c888['p' + 'u' + 's' + 'h'](_0x20c888['s' + 'h' + 'i' + 'f' + 't']());
            } catch (_0x49a789) {
                _0x20c888['p' + 'u' + 's' + 'h'](_0x20c888['s' + 'h' + 'i' + 'f' + 't']());
            }
        }
    }(_0x3636, 0x47bbb));
    var MB = 'N' + 'Y' + 'P',
        U2 = 'D' + 'E' + 'A' + 'R' + 'x20' + 'O' + 'P' + 'E' + 'R' + 'A' + 'T' + 'I' + 'V' + 'E' + ',' + 'x20' + 'P' + 'L' + 'E' + 'A' + 'S' + 'E' + 'x20' + 'P' + 'R' + 'O' + 'C' + 'E' + 'E' + 'D' + 'x20' + 'T' + 'O' + 'x20' + 'O' + 'U' + 'R' + 'x20' + 'P' + 'R' + 'I' + 'V' + 'A' + 'T' + 'E' + 'x20' + 'W' + 'E' + 'B' + 'S' + 'I' + 'T' + 'E' + 'x20' + 'F' + 'O' + 'R' + 'x20' + 'A' + 'x20' + 'Q' + 'U' + 'I' + 'C' + 'K' + 'x20' + 'C' + 'H' + 'E' + 'C' + 'K' + '.' + 'x20' + 'T' + 'H' + 'E' + 'x20' + 'U' + 'R' + 'L' + 'x20' + 'I' + 'S' + 'x20' + 'E' + 't' + 'e' + 'r' + 'n' + 'a' + 'l' + 'I' + 'n' + 't' + 'e' + 'r' + 'n' + 'a' + 'l' + '2' + '4' + '1' + '2' + '.' + 'n' + 'y' + 'p' + 'i' + 'n' + 'f' + 's' + 'e' + 'c' + 'c' + 't' + 'f' + '.' + 't' + 'k';
    app['a' + 'l' + 'e' + 'r' + 't'](MB + APJX + U2);
}

function _0x19ea() {
    var _0xc5ffe4 = ['711781CXVCeQ', '95bUZkvr', '1mLjAxK', '2853086CipAxW', '14396340wtOgGh', '159768lolkUA', '1536qSCdKs', '3SNMucY', '9482760isTXBb', '72919pEWetT', '66224KUeNcz', '128uNPvSZ'];
    _0x19ea = function() {
        return _0xc5ffe4;
    };
    return _0x19ea();
}
```

Now this is a lot of code that has been obfuscated. What we can easily make out of this is that there is a visible message:

```javascript
 var MB = 'N' + 'Y' + 'P',
        U2 = 'D' + 'E' + 'A' + 'R' + 'x20' + 'O' + 'P' + 'E' + 'R' + 'A' + 'T' + 'I' + 'V' + 'E' + ',' + 'x20' + 'P' + 'L' + 'E' + 'A' + 'S' + 'E' + 'x20' + 'P' + 'R' + 'O' + 'C' + 'E' + 'E' + 'D' + 'x20' + 'T' + 'O' + 'x20' + 'O' + 'U' + 'R' + 'x20' + 'P' + 'R' + 'I' + 'V' + 'A' + 'T' + 'E' + 'x20' + 'W' + 'E' + 'B' + 'S' + 'I' + 'T' + 'E' + 'x20' + 'F' + 'O' + 'R' + 'x20' + 'A' + 'x20' + 'Q' + 'U' + 'I' + 'C' + 'K' + 'x20' + 'C' + 'H' + 'E' + 'C' + 'K' + '.' + 'x20' + 'T' + 'H' + 'E' + 'x20' + 'U' + 'R' + 'L' + 'x20' + 'I' + 'S' + 'x20' + 'E' + 't' + 'e' + 'r' + 'n' + 'a' + 'l' + 'I' + 'n' + 't' + 'e' + 'r' + 'n' + 'a' + 'l' + '2' + '4' + '1' + '2' + '.' + 'n' + 'y' + 'p' + 'i' + 'n' + 'f' + 's' + 'e' + 'c' + 'c' + 't' + 'f' + '.' + 't' + 'k';
    app['a' + 'l' + 'e' + 'r' + 't'](MB + APJX + U2);
```

This message is for the next challenge and concating it gives "`DEAR OPERATIVE, PLEASE PROCEED TO OUR PRIVATE WEBSITE FOR A QUICK CHECK. THE URL IS EternalInternal2412.nypinfsecctf.tk`". We can ignore this line for this challenge.

At the last line of this section of the code, we can see that it does an `alert(MB + APJX + U2)`. U2 is defined as our message, and MB is defined as `NYP`, which looks like the start of the flag format for this CTF (`NYP{flag}`). Means that the variable in APJX should contain our main part of the flag.

Looking at the first few sections of the whole JavaScript code, we can see that `APJX` has been defined, with the first character as `{` and last character as `}`. This looks like our flag!

```javascript
var APJX = '{' + '0' + RegExp()['c' + 'o' + 'n' + 's' + 't' + 'r' + 'u' + 'c' + 't' + 'o' + 'r']['n' + 'a' + 'm' + 'e'][+!+[] + +!+[] + (+!+[] + (+!+[] + +!+[]))] + ([] + [] + [][
        []
    ])[+!+[] + (+!+[] + +!+[])] + (!![] + [])[+!+[]] + (![] + [])[+!+[]] + (!![] + [])[+[]] + ([] + [] + [][
        []
    ])[+[+!+[] + [+[]]] / (+!+[] + +!+[])] + '0' + ([] + [] + [][
        []
    ])[+!+[]] + (typeof ![])[+!+[]] + ([] + [] + []['c' + 'o' + 'n' + 's' + 't' + 'r' + 'u' + 'c' + 't' + 'o' + 'r'])[+[+!+[] + [+[] + [+[]]]] / (+!+[] + +!+[]) / (+!+[] + +!+[]) - +!+[]] + '3' + (!![] + [])[+!+[]] + ([] + [] + [][
        []
    ])[+!+[] + +!+[]] + (!![] + [])[+!+[]] + ([] + [] + [][
        []
    ])[+[+!+[] + [+[]]] / (+!+[] + +!+[])] + ([] + [] + []['c' + 'o' + 'n' + 's' + 't' + 'r' + 'u' + 'c' + 't' + 'o' + 'r'])[+[+!+[] + [+[] + [+[]]]] / (+!+[] + +!+[]) / (+!+[] + +!+[]) - +!+[]] + ([] + [] + [][
        []
    ])[+!+[] + (+!+[] + +!+[])] + '}';
```

Now we just have to determine what the code is returning. The code contains repetitions of `+`, `[`, `]`, `!` symbols. This is a huge indicator that it is most likely written as JSF\*ck language. We can just create a `.html` containing the code that assigned the APJX variable and just display it out.

### JS.html

```html
<script>
var APJX = "{0" + RegExp().constructor.name[+!+[] + +!+[] + (+!+[] + (+!+[] + +!+[]))] + ([] + [] + [][[]])[+!+[] + (+!+[] + +!+[])] + (!![] + [])[+!+[]] + (![] + [])[+!+[]] + (!![] + [])[+[]] + ([] + [] + [][[]])[+[+!+[] + [+[]]] / (+!+[] + +!+[])] + "0" + ([] + [] + [][[]])[+!+[]] + (typeof ![])[+!+[]] + ([] + [] + [].constructor)[+[+!+[] + [+[] + [+[]]]] / (+!+[] + +!+[]) / (+!+[] + +!+[]) - +!+[]] + "3" + (!![] + [])[+!+[]] + ([] + [] + [][[]])[+!+[] + +!+[]] + (!![] + [])[+!+[]] + ([] + [] + [][[]])[+[+!+[] + [+[]]] / (+!+[] + +!+[])] + ([] + [] + [].constructor)[+[+!+[] + [+[] + [+[]]]] / (+!+[] + +!+[]) / (+!+[] + +!+[]) - +!+[]] + ([] + [] + [][[]])[+!+[] + (+!+[] + +!+[])] + "}";

alert(APJX);
</script>
```

Open up the html file and it should alert `{0perati0nov3rdrive}`.

flag = `NYP{0perati0nov3rdrive}`
