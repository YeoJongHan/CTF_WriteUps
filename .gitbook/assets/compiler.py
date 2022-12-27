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
