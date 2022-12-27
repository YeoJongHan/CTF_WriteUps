#!/usr/bin/env python3

from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from itertools import cycle
from secret import flag

def xor(msg:bytes,key:bytes)->bytes:
  return ''.join([chr(a^b) for a,b in zip(msg,cycle(key))]).encode('utf-8')

class My_ECB:
  def __init__(self):
    self.__key = get_random_bytes(16)
    self.__cipher = AES.new(self.__key, AES.MODE_ECB)
  
  def encrypt(self, data:str,iv:bytes)->str:
    if len(data)%16>0:
      data = pad(data.encode('utf-8'), AES.block_size)
    else:
      data = data.encode()
    ct_1 = self.xor_ecb(data,iv)
    ct_bytes = self.__cipher.encrypt(ct_1)
    ct = b64encode(ct_bytes).decode('utf-8')
    return ct

  def decrypt(self,msg:str,iv:bytes)->str:
    try:
      msg = b64decode(msg.encode('utf-8'))
      ct_1 = self.__cipher.decrypt(msg)
    except:
      return None
    data = self.xor_ecb(ct_1,iv)
    try:
      pt = unpad(data,AES.block_size).decode('utf-8')
    except:
      pt = data.decode('utf-8')
    return pt

  def xor_ecb(self,data:bytes,key:bytes)->bytes:
    blocks = [data[i:i+16] for i in range(0,len(data),16)]
    result = b''
    for block,val in zip(blocks,cycle(list(key))):
      result += xor(block,chr(val).encode('utf-8'))
    assert len(result) == len(data)
    return result


if __name__ == "__main__":
  assert len(flag) == 16

  print('''
$$\   $$\  $$$$$$\  $$$$$$$\   $$$$$$\   $$$$$$\  $$\       $$$$$$$$\ 
$$ |  $$ |$$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$ |      $$  _____|
\$$\ $$  |$$ /  $$ |$$ |  $$ |$$ /  $$ |$$ /  \__|$$ |      $$ |      
 \$$$$  / $$ |  $$ |$$$$$$$  |$$$$$$$$ |$$ |      $$ |      $$$$$\    
 $$  $$<  $$ |  $$ |$$  __$$< $$  __$$ |$$ |      $$ |      $$  __|   
$$  /\$$\ $$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$\ $$ |      $$ |      
$$ /  $$ | $$$$$$  |$$ |  $$ |$$ |  $$ |\$$$$$$  |$$$$$$$$\ $$$$$$$$\ 
\__|  \__| \______/ \__|  \__|\__|  \__| \______/ \________|\________|
  ''')
  print('A service to encrypt and decrypt any strings for free, but you can only decrypt once per encryption!\n')
  while True:
    e = My_ECB()
    data = str(input("Enter a string to encrypt (-1): "))
    if data == '-1':
      break
    result = e.encrypt(data,flag)
    print(">>>",result)
    data = str(input("Enter a base64 encoded ciphertext (-1): "))
    if data == '-1':
      break
    result = e.decrypt(data,flag)
    if result == None:
      print("No no, that ain't right.")
    else:
      print(">>>",result)
