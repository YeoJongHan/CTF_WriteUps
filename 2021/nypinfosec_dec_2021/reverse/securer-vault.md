# Securer Vault

## Description

> Dear Secret Agent,

> After you broke the previous vault, the EternalWinter group has make their web portal harder to attack! Time is running out, can you solve this in time?

> Author: **Edwin**

We are provided with a link: [http://securer-vault.nypinfsecctf.tk/](http://securer-vault.nypinfsecctf.tk/)

## The Challenge

Upon visiting the site provided, we are redirected to a login page ![Picture1](https://user-images.githubusercontent.com/83258849/147594105-ea9ee79a-c8c5-41ff-b702-07b97ab777fb.png)

Seems like we need to figure out the password.

Trying `';--`, `' or 1=1;--`, and `' or '1'='1';--` didn't seem to work and didn't return any useful information. Seems like it may **not** be vulnerable to SQL Injection.

By viewing the source code of the page through `Inspect Element`, we can see how to password is checked through a JavaScript function.

![Picture2](https://user-images.githubusercontent.com/83258849/147594529-2c15926f-92fc-4e82-b392-9470de47f97a.png)

### Examining the checkPassword() function

```javascript
const checkPassword = () => {
		const check = document.getElementById("password").value;
		const password = Array.from(check).map(a => 0xCafe + a.charCodeAt(0));


		if (
			password[4] === 52048 &&
			password[2] === 52081 &&
			password[7] === 52067 &&
			password[3] === 52087 &&
			password[8] === 52080 &&
			password[11] === 52076 &&
			password[10] === 52071 &&
			password[0] === 52035 &&
			password[6] === 52084 &&
			password[9] === 52081 &&
			password[1] === 52063 &&
			password[5] === 52067 &&
			password[12] === 52069
		)

		{
			window.location.replace(check + ".html");
		} else {
			alert("Wrong password!");
		}
	}
```

The script first takes the value of the password that the user inputs and puts it into a constant named `check`:

```javascript
const check = document.getElementById("password").value;
```

It then forms an **array** from the user input and **maps** every character in the user input, converts the character from ASCII to decimal, then adds `0xCafe, which is 51966` to the decimal.

```javascript
const password = Array.from(check).map(a => 0xCafe + a.charCodeAt(0));
```

Afterwards, it checks each character in the array if it is a specific number, and redirects the user to another endpoint if the if statement is True.

We can simply create a python script to loop through all the numbers and indexes, minus 0xCafe from each of the numbers, and convert them back to ASCII.

```python
pwd = {
	"4" : 52048,
	"2" : 52081,
	"7" : 52067,
	"3" : 52087,
	"8" : 52080,
	"11" : 52076,
	"10" : 52071,
	"0" : 52035,
	"6" : 52084,
	"9" : 52081,
	"1" : 52063,
	"5" : 52067,
	"12" : 52069
}

final = ""

for i in range(13):
	num = pwd[str(i)] - 0xCafe
	final += chr(num)

print(final)
```

Output: `EasyReversing`

Input `EasyReversing` into the password field and it will redirect the user to a page containing the flag.

flag = `NYP{lAtt3_l3ss_suGar}`
