# Interesting Story

> Dear Secret Agent,

> Have you read this book before?

> Author: **Edwin**

We are provided a text file `interesting_story.txt`

## The Challenge

The text file contains a long, interesting story indeed.

Taking a quick glance, nothing looks out of the ordinary except for "`November The real reason was so...`" and "`Yankee Ninety-nine percent of the time...`"

![story](https://user-images.githubusercontent.com/83258849/147766869-a02d9e29-8efa-49ca-aaf4-6006fff182dc.png)

Notice how the capital letters of the out-of-place words form our first two letters of the flag format `NYP{flag}`? Seems like the flag is hidden in this manner, adding extra words to a story.

Let's find the original story first by extracting one or two unique line of text and using our best friend **Google**. I searched for `As the group single-files through the door, I fall in at the back of the line. The guy ahead of me reaches the door, notices there’s someone behind him, takes a quick glance to make sure I’m wearing a company badge, and holds the door open for me.`

Looks like the story used was from the prologue of the book `Ghost in the Wires: My Adventures as the World's Most Wanted Hacker`. Interesting story about hacking.

Using the original prologue and the `interesting_story.txt`, we can create a python script to compare them and return the new words that have been added. Note that I had to format the two different stories so that the script would return the correct results.

```python
f = open('formatted_interesting_story.txt', 'r').read()
a = open('actual_story.txt', 'r').readlines()

story = ""

for i in a:
	story += i.replace('\n', ' ')

fl = f.split(" ")
sl = story.split(" ")

new = []

for i in fl:
	if i not in sl:
		new.append(i)

print(new)
```

Output: `['November', 'Yankee', 'Papa{', 'Kilo', 'terrathree', 'Victor', 'unaone.', 'November', 'Mike', 'leave', 'unaone.', 'Tango', '—recovering', 'November', 'days', 'unaone.', 'Charlie', 'Kilo}.']`

There are some strings like `leave`, `-recovering`, and `days` which are false positives, so we can just ignore them. What about `terrathree` and `unaone`?

If we grab the first letters of each of the strings and join them together, we will get somewhat of a disfigured flag `NYPKtVuNMuTNNuCK`. But since `terrathree` has a `three` in the word and `unaone` has a `one` in the word, let's just substitute them for their numbers: `NYPK3V1NM1TN1CK`. That looks better, now to add in the curly brackets.

flag = `NYP{K3V1NM1TN1CK}`

### As pointed out by `Dylan`, these words like 'November', 'Papa', 'unaone', 'terrathree'... are in `NATO Phonetic Alphabet` and can be decoded through the `NATO Phonetic Alphabet Decoder` https://www.dcode.fr/nato-phonetic-alphabet. Thank you for pointing that out :D

> _The stories and full python script are under the `tools` folder :)_
