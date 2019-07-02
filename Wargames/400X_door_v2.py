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
	context.binary = "./door"
	
	fin = 0
	stage = 0
	
	while(fin < 1):
		if(stage == 0):
			io = io_beg()						
				
			io.recvuntil("A landslide has blocked the way at".encode(ENCODING))
			peculiar_addr = io.recvline().decode(ENCODING).strip()
			peculiar_addr_int = int(peculiar_addr, 16)
				
			io_rdy(io)
			buf = toHexCustom(peculiar_addr_int)
			print("peculiar addr: "+buf)
			
			
				
					
			io.interactive()
			stage = stage + 1
				
		else:
			print("I think I'm done :)")
			fin = 1

if __name__ == '__main__':
	main()
