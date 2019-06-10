#!/usr/bin/python3

from pwn import *
import binascii

def main():
	PROGRAM_NAME = "1000"
	encoding = "ascii"
	r = remote('plzpwn.me', 1000)
	stage = 0
	fin = 0
	
	while(fin < 1):
		if(stage == 0): #decimal begin
			r.recvuntil("Lets see if you can strip out this address:".encode(encoding))
			print("0. strip")
			soup = r.recvuntil("}".encode(encoding)).decode(encoding)
			print("soup: "+soup)
			
			pick = find_between(soup, "x", "}") # HEX
			buf = int(pick, 16)
			buf = str(buf)
			
			print("sending: "+buf)
			r.sendline(buf.encode(encoding))
			
			stage+=1
		elif (stage == 1): #minus 
			print("1. minus")
			#skip human text
			r.recvuntil("Now send it back to me in hex form MINUS".encode(encoding))
			r.recvuntil("0x".encode(encoding))
			# soup business
			soup = r.recvuntil("!".encode(encoding)).decode(encoding) # 0x---ABCD!--\n...
			pick = soup[:-1] # 0x--ABCD--!\n...
			buf = int(buf) - int(pick, 16)
			
			print("buf (dec): "+str(buf))
			buf = hex(buf)
			print("buf (hex): "+buf)
			
			print("sending: "+buf)
			r.sendline(buf.encode(encoding))
			
			stage+=1
		elif (stage == 2): # to little endian
			#skip human text
			print("2. lil endian")
			r.recvuntil("Now send me 0x".encode(encoding), timeout=10) #Now send me 0x
			soup = r.recvuntil("in little endian form!".encode(encoding)).decode(encoding) # 0x--ABCD in little...
			print("soup: "+soup)
			pick = soup.replace("in little endian form!", "").strip() #ABCD
			print("pick: "+pick)
			buf2 = toEndian(int(pick,16), "little")
			buf2 = str(hex(buf2))
			
			r.sendline(buf2.encode(encoding))
			
			stage+=1
		elif (stage == 3):#secret
			r.sendline("secret".encode(encoding))
		else:
			print("Weird flex")
			r.interactive()
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

def toHexCustom(dec): 
	return str(hex(dec).split('x')[-1])	
	
# my own wrapper
def toEndian(i, e):
	buf = int2bytes(i)
	buf = int.from_bytes(buf, e)
	return buf

# https://stackoverflow.com/a/28524760
# import binascii
def int2bytes(i):
    hex_string = '%x' % i
    n = len(hex_string)
    return binascii.unhexlify(hex_string.zfill(n + (n & 1)))

if __name__ == '__main__':
	main()
	
