#!/usr/bin/python3

from pwn import *

def main():
	PROGRAM_NAME = "1001"
	encoding = "ascii"
	r = remote('plzpwn.me', 1001)
	stage = 0
	fin = 0
	
	while(fin < 1):
		if(stage == 0):
			r.recvuntil("math".encode(encoding))
			print("Math start!")
			r.recvuntil("out!\n".encode(encoding))
			stage = 1
		elif(stage == 1): #uses header
			header = r.recvn(1).decode(encoding)
			print("header: "+header)
			
			buf = header.isnumeric()
			
			if(header.isnumeric()): #is number? All good
				print("doing maths")
				
				buf = r.recvuntil("+".encode(encoding)).decode(encoding)[:-2]
				first = int(str(header)+buf.strip())
				print("first: "+str(first))
				
				buf = r.recvuntil("=".encode(encoding)).decode(encoding)[:-2]
				second = int(buf.strip())				
				print("second: "+str(second))
				
				result = str(first+second)
				print("result: "+str(result))
				
				r.sendline(result.encode(encoding))
				
				buf = r.recvuntil("Answer!\n".encode(encoding)).decode(encoding)
				print(buf)
			else:
				print("no more maths")
				stage = 2
		elif(stage == 2): #try for shell
			buf = r.recvline().decode(encoding)
			print("try anything")
			print(buf)
			r.sendline("secret".encode(encoding))
			
			print("waiting for a lil more")
			buf = r.recvline(timeout=10).decode(encoding)
			
			stage = 4
		elif(stage == 3):
			try:
				buf = str(raw_input(">>: ").decode(encoding))
				
				#print("input: "+buf)
				r.sendline(buf.encode(encoding))
				
				#buf = r.recv().decode(encoding)
				#print(buf)
				endofinput = 0
				while(not(endofinput)):
					try:
						buf = r.recv(timeout=2).decode(encoding)
						print(buf, end='')
					except Exception:
						endofinput = 1
						pass
					
			except KeyboardInterrupt:
				fin = 1
		elif(stage == 4):
			buf = r.interactive()
		else:
			print("Weird flex, exiting")
			fin = 1
			
	print("cya!")
			

# https://stackoverflow.com/a/3368991
def find_between( s, first, last ):
    try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""

def find_between_r( s, first, last ):
    try:
        start = s.rindex( first ) + len( first )
        end = s.rindex( last, start )
        return s[start:end]
    except ValueError:
        return ""

if __name__ == '__main__':
	main()
	
