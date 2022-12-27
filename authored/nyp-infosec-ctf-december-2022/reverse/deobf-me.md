# Deobf Me

| Difficulty | Points |
| ---------- | ------ |
| Medium     | 300    |

## Description

> The symbols are speaking, what do they want?

{% file src="../../../.gitbook/assets/chall (1).py" %}

{% file src="../../../.gitbook/assets/compiler.py" %}

## Solution

### TL;DR

#### Long Method

1. One way is to replace the lambda functions with actual functions.
2. Seeing what they do in the `compiler.py`, we can replicate those functions in order to remove the lambda and print the flag.

#### Quick Method

1. Find the portion of the code which represents the flag.
2. Replace "Give it another try!" with the code so it prints out the flag.
3. win

{% hint style="info" %}
Can be written in 4 lines of Python code.
{% endhint %}

### Analysis

We can basically see that `chall.py` contains our obfuscated code. Running `python3 chall.py`, we are prompted for the flag.

<figure><img src="../../../.gitbook/assets/image (13).png" alt=""><figcaption><p>chall.py Program</p></figcaption></figure>

We are also given the compiler that presumably creates the code in `chall.py`.

<details>

<summary>compiler.py</summary>

```python
#!/usr/bin/env python3

# Created by Jong Han, thank me later

import random, string
from secret import flag

def eval_obf(x:int)->str:
  global c5; global c6
  add_funcs={'+1':c5,'+2':c6}
  starters=[1,0]
  counter = random.choice(starters)
  result = str(counter)
  while counter < x:
    chosen_func = random.choice(list(add_funcs.values()))
    if chosen_func == add_funcs['+1']:
      counter += 1
    else:
      counter += 2
    if counter > x:
      tmp_list = list(add_funcs.values())
      tmp_list.remove(chosen_func)
      chosen_func = tmp_list[0]
    result =  chosen_func + '(' + result + ')'
  return result

def str_to_chrs(x:str,func_of_chr:str,obf_method:callable)->str:
  return '+'.join(map(lambda a:f'{func_of_chr}('+obf_method(ord(a))+')',x))

def initialize(code:str,flag:str)->str:
  global c1; global c2; global c3; global c4; global c5; global c6; global c7; global c8; global c9
  c1,c2,c3,c4,c5,c6,c7,c8,c9 = random.sample(string.ascii_lowercase,9)


  l = 'lambda'
  char = str_to_chrs('chr','chr',str)
  ladd1 = str_to_chrs('lambda a:a+1',c2,str)
  ladd2 = str_to_chrs('lambda b:b+2',c2,str)
  code = str_to_chrs(code,c4,eval_obf)
  p = str_to_chrs('print',c4,str)
  ifstr = str_to_chrs('if',c4,str)
  flag_obf = str_to_chrs(flag,c4,eval_obf)
  result = f'({l} {c1}:({l} {c1},{c2}:({l} {c3},{c4},{c5},{c6}:(lambda {c7},{c8},{c9}: {c9}("You R l33t Python RE master.") if {c7}=={c8} else {c9}("Give it another try!"))({c3}({code}),{flag_obf},{c3}({p})))({c1},{c2},({c1}({ladd1})),({c1}({ladd2}))))({c1},{c1}({char})))(eval)'
  return result

code = 'input("Enter flag: ")'
with open('chall.py','w') as f: f.write(initialize(code,flag))

```

</details>

We can see in `compiler.py` that the `flag` and the `input(...)` code are given as arguments into the `initalize` function.

```python
with open('chall.py','w') as f: f.write(initialize(code,flag))
```

In the initialize function, we see that the `result` variable is the important one to focus on as it returns the code in `chall.py`. I have rearranged result so that it can be understood more easily.

```python
({l} {c1}:
({l} {c1},{c2}:
({l} {c3},{c4},{c5},{c6}:
(lambda {c7},{c8},{c9}: {c9}("You R l33t Python RE master.") if {c7}=={c8} else {c9}("Give it another try!"))
({c3}({code}),{flag_obf},{c3}({p})))
({c1},{c2},({c1}({ladd1})),({c1}({ladd2}))))
({c1},{c1}({char})))
(eval)
```

### Solving Through The Long Method

Analyzing `result`, we see that the `eval` function will always be passed into `c1`.

So {c1}({char}) means it just evaluates `char` into the `chr` function. This is then passed into c2 in the next lambda function.

We then see that eval(ladd1) and eval(ladd2) is made, where ladd1 and ladd2 are just functions to add 1 and add 2 to the given number respectively.

So in the next lambda function, we can see `c3`=eval(), `c4`=chr(), `c5`=+1func, `c6`=+2func. We can verify that we have identified `c5` and `c6` correctly as it is provided in the `eval_obf` function as `+1` and `+2` respectively.

In the next lambda function, we can see that `c7`=eval(input("Enter flag: ")), `c8`=`flag_obf`, and `c9`=eval("print") (which is basically the print function))

We go back to looking at the `flag_obf` variable. It is provided as an argument into the last lambda function. We can filter and take in only the portion of the obfuscated code where `({c3}({code}),{flag_obf},{c3}({p})))`, create our own functions for `c3`,`c4`,`c5`,`c6`, and evaluate `print(flag_obf)`

{% tabs %}
{% tab title="long_solve.py" %}
```python
#!/usr/bin/env python3
import re

def c3_func(c):
    print(c)
    return eval(c)

def c4_func(c):
    return chr(c)

def c5_func(c):
    return c+1

def c6_func(c):
    return c+2
    
obfcode = open ('chall.py','r').read()
simplified_code = obfcode.split('("Give it another try!"))(')[1]
c1 = re.search(r'lambda [a-z]:',obfcode)[0][-2]
simplified_code = simplified_code.split(f'))({c1}')[0]
find_c = re.search(r'lambda ([a-z],){3}[a-z]',obfcode)[0].split('lambda ')[-1]
c3,c4,c5,c6 = find_c.split(',')
exec(f'{c3}=c3_func;{c4}=c4_func;{c5}=c5_func;{c6}=c6_func')
eval_code, flag, eval_print = simplified_code.split(',')
eval(f"print({flag})")

```
{% endtab %}
{% endtabs %}

### Solving Through The Quick Method

This just replaces the "Give it another try!" string with the flag.

We can easily find the obfuscated flag by using the `,` as a delimiter.

{% tabs %}
{% tab title="quick_solve.py" %}
```python
obfcode = open ('chall.py','r').read()
flagcode = obfcode.split(',')[7]
code = obfcode.replace('"Give it another try!"',flagcode)
eval(code)
```
{% endtab %}
{% endtabs %}

