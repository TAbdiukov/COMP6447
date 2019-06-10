#!/usr/bin/python3

from pwn import *

def main():
	PROGRAM_NAME = "1001"
	encoding = "ascii"
	r = remote('plzpwn.me', 1001)
	fin = 0
	while(not(fin)):
		buf = r.recvline().decode(encoding)
		
		if(buf.find('math') != -1):
			print("math start!")
		elif(buf.find(" + ") != -1):
			first = int(find_between(buf, "", " + ").strip())
			second = int(find_between(buf, str(first)+" + ", " =").strip())
			result = str(first+second)
			#print("first: "+str(first))
			#print("second: "+str(second))
			print("result: "+str(result))
			r.sendline(result.encode(encoding))
		else:
			print("Unknown")
			print(buf)
			r.sendline("secret".encode(encoding))
			print("closing now")
			fin = 1
			

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
	
